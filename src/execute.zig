//! Stateless block execution pipeline for the Zisk zkVM guest.
//!
//! Adapted from zevm-stateless/src/main.zig:
//!   - std.debug.print  → UART writes via main.uartWrite
//!   - std.heap.page_allocator / c_allocator → caller-provided allocator
//!   - std.process.exit → error returns
//!   - stdin / file I/O → caller-provided byte slice
//!
//! Pipeline:
//!   Phase 1 — MPT proof verification against the pre-execution state root
//!   Phase 2 — WitnessDatabase construction from proven state
//!   Phase 3 — EVM block execution via zevm
//!
//! TODO (zevm-stateless integration):
//!   - Replace InMemoryDB with WitnessDatabase once it implements the
//!     zevm Database trait (tracked in zevm-stateless/src/db/main.zig)
//!   - Add post-execution state root computation (Merkle trie rebuild)

const std          = @import("std");
const deserialize  = @import("deserialize.zig");
const input_mod    = @import("input");
const output_mod   = @import("output");
const primitives   = @import("primitives");
const mpt          = @import("mpt");
const context_mod  = @import("context");
const handler_mod  = @import("handler");
const database_mod = @import("database");
const bytecode_mod = @import("bytecode");
const state_mod    = @import("state");

const uartWrite = @import("main.zig").uartWrite;

/// Execute a full stateless block from its binary-encoded StatelessInput.
/// Returns a ProofOutput that the guest commits to.
pub fn executeBlock(
    allocator:  std.mem.Allocator,
    input_data: []const u8,
) !output_mod.ProofOutput {
    const si = try deserialize.fromBytes(allocator, input_data);

    uartWrite("=== zevm-stateless-zisk ===\n");

    // ── Phase 1: MPT proof verification ──────────────────────────────────────
    uartWrite("Phase 1  MPT proof verification\n");
    {
        var phase1_ok = true;
        var current_addr: ?primitives.Address = null;

        for (si.witness.keys, 0..) |key, i| {
            _ = i;
            if (key.len == 20) {
                var addr: primitives.Address = undefined;
                @memcpy(&addr, key[0..20]);
                current_addr = addr;

                const key_hash = mpt.keccak256(&addr);
                _ = mpt.verifyProof(si.witness.state_root, key_hash, si.witness.nodes) catch |e| {
                    uartWrite("  FAIL account proof: ");
                    uartWrite(@errorName(e));
                    uartWrite("\n");
                    phase1_ok = false;
                    continue;
                };

            } else if (key.len == 52) {
                var addr: primitives.Address = undefined;
                @memcpy(&addr, key[0..20]);
                current_addr = addr;
                var slot: primitives.Hash = undefined;
                @memcpy(&slot, key[20..52]);

                const acct = mpt.verifyAccount(si.witness.state_root, addr, si.witness.nodes) catch |e| {
                    uartWrite("  FAIL account (storage): ");
                    uartWrite(@errorName(e));
                    uartWrite("\n");
                    phase1_ok = false;
                    continue;
                };
                if (acct) |a| {
                    const slot_key_hash = mpt.keccak256(&slot);
                    _ = mpt.verifyProof(a.storage_root, slot_key_hash, si.witness.nodes) catch |e| {
                        uartWrite("  FAIL storage proof: ");
                        uartWrite(@errorName(e));
                        uartWrite("\n");
                        phase1_ok = false;
                        continue;
                    };
                }

            } else if (key.len == 32) {
                var slot: primitives.Hash = undefined;
                @memcpy(&slot, key[0..32]);

                if (current_addr) |addr| {
                    const acct = mpt.verifyAccount(si.witness.state_root, addr, si.witness.nodes) catch |e| {
                        uartWrite("  FAIL account (slot32): ");
                        uartWrite(@errorName(e));
                        uartWrite("\n");
                        phase1_ok = false;
                        continue;
                    };
                    if (acct) |a| {
                        const slot_key_hash = mpt.keccak256(&slot);
                        _ = mpt.verifyProof(a.storage_root, slot_key_hash, si.witness.nodes) catch |e| {
                            uartWrite("  FAIL slot proof: ");
                            uartWrite(@errorName(e));
                            uartWrite("\n");
                            phase1_ok = false;
                            continue;
                        };
                    }
                }
            }
        }

        if (!phase1_ok) return error.MptVerificationFailed;
    }
    uartWrite("  OK  MPT verification passed\n");

    // ── Phase 2: WitnessDatabase construction ─────────────────────────────────
    uartWrite("Phase 2  Building WitnessDatabase\n");

    // TODO: Replace with WitnessDatabase once it implements the zevm
    //       Database interface.  For now, load proven state into InMemoryDB.
    var in_mem_db = database_mod.InMemoryDB.init(allocator);

    for (si.witness.keys) |key| {
        if (key.len == 20) {
            var addr: primitives.Address = undefined;
            @memcpy(&addr, key[0..20]);
            if (mpt.verifyAccount(si.witness.state_root, addr, si.witness.nodes) catch null) |a| {
                in_mem_db.insertAccount(addr, state_mod.AccountInfo{
                    .balance   = a.balance,
                    .nonce     = a.nonce,
                    .code_hash = a.code_hash,
                    .code      = null,
                }) catch {};
            }
        } else if (key.len == 52) {
            var addr: primitives.Address = undefined;
            @memcpy(&addr, key[0..20]);
            var slot: primitives.Hash = undefined;
            @memcpy(&slot, key[20..52]);
            if (mpt.verifyAccount(si.witness.state_root, addr, si.witness.nodes) catch null) |a| {
                const slot_key = std.mem.readInt(u256, &slot, .big);
                const val = mpt.verifyStorage(a.storage_root, slot, si.witness.nodes) catch 0;
                in_mem_db.insertStorage(addr, slot_key, val) catch {};
            }
        }
    }

    for (si.witness.codes) |code_bytes| {
        const h = mpt.keccak256(code_bytes);
        in_mem_db.insertCode(h, bytecode_mod.Bytecode.newLegacy(code_bytes)) catch {};
    }

    // ── Phase 3: EVM block execution ─────────────────────────────────────────
    uartWrite("Phase 3  Executing block transactions\n");

    var block_env = context_mod.BlockEnv.default();
    block_env.number      = @as(primitives.U256, si.block.number);
    block_env.timestamp   = @as(primitives.U256, si.block.timestamp);
    block_env.gas_limit   = si.block.gas_limit;
    block_env.beneficiary = si.block.beneficiary;
    block_env.basefee     = si.block.base_fee_per_gas orelse 0;
    block_env.difficulty  = si.block.difficulty;
    block_env.prevrandao  = si.block.mix_hash;
    if (si.block.excess_blob_gas) |ebg| {
        block_env.setBlobExcessGasAndPrice(ebg, primitives.BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE);
    }

    const spec = primitives.SpecId.prague;
    var ctx = context_mod.Context.new(in_mem_db, spec);
    ctx.block = block_env;

    var instructions = handler_mod.Instructions.new(spec);
    var precompiles  = handler_mod.Precompiles.new(spec);

    var total_gas_used: u64 = 0;

    for (si.transactions, 0..) |tx, i| {
        _ = i;
        ctx.tx.tx_type    = tx.tx_type;
        ctx.tx.caller     = [_]u8{0} ** 20;
        ctx.tx.nonce      = tx.nonce;
        ctx.tx.gas_limit  = tx.gas_limit;
        ctx.tx.value      = tx.value;
        ctx.tx.chain_id   = tx.chain_id;
        ctx.tx.kind       = if (tx.to) |to|
            context_mod.TxKind{ .Call = to }
        else
            context_mod.TxKind.Create;

        switch (tx.tx_type) {
            2, 3, 4 => {
                ctx.tx.gas_price        = tx.gas_price;
                ctx.tx.gas_priority_fee = tx.gas_priority_fee;
            },
            else => {
                ctx.tx.gas_price        = tx.gas_price;
                ctx.tx.gas_priority_fee = null;
            },
        }

        ctx.tx.data = null;
        if (tx.data.len > 0) {
            var data_list = std.ArrayList(u8){};
            data_list.appendSlice(allocator, tx.data) catch {};
            ctx.tx.data = data_list;
        }

        if (ctx.tx.blob_hashes) |*old| old.deinit(allocator);
        if (tx.tx_type == 3 and tx.blob_hashes.len > 0) {
            var bh_list = std.ArrayList(primitives.Hash){};
            bh_list.appendSlice(allocator, tx.blob_hashes) catch {};
            ctx.tx.blob_hashes          = bh_list;
            ctx.tx.max_fee_per_blob_gas = tx.max_fee_per_blob_gas;
        } else {
            ctx.tx.blob_hashes          = null;
            ctx.tx.max_fee_per_blob_gas = 0;
        }
        ctx.tx.authorization_list = null;

        var frame_stack = handler_mod.FrameStack.new();
        var evm = handler_mod.Evm.init(&ctx, null, &instructions, &precompiles, &frame_stack);

        const exec_result = handler_mod.ExecuteEvm.execute(&evm) catch |err| {
            uartWrite("  tx ERROR: ");
            uartWrite(@errorName(err));
            uartWrite("\n");
            if (ctx.tx.data) |*d| d.deinit(allocator);
            ctx.tx.data = null;
            continue;
        };

        if (ctx.tx.data) |*d| d.deinit(allocator);
        ctx.tx.data = null;

        total_gas_used += exec_result.gas_used;
    }

    uartWrite("  OK  execution complete\n");

    // TODO: Compute post-execution state root from modified in_mem_db state
    //       (requires Merkle trie reconstruction from the dirty state).
    //       For now, return zeroed post_state_root and receipts_root as
    //       placeholders so the output pipeline can be tested end-to-end.
    return output_mod.ProofOutput{
        .pre_state_root  = si.witness.state_root,
        .post_state_root = [_]u8{0} ** 32, // TODO
        .receipts_root   = [_]u8{0} ** 32, // TODO
        .receipts        = &.{},
    };
}
