//! Binary deserializer for the StatelessInput format.
//!
//! Adapted from zevm-stateless/src/deserialize.zig for the freestanding Zisk
//! zkVM target.  The only behavioural difference is that input comes from a
//! caller-provided byte slice (`fromBytes`) rather than from stdin.
//!
//! TODO: upstream a `pub fn fromBytes` into zevm-stateless's deserialize.zig
//!       so this local copy can be removed.

const std        = @import("std");
const input_mod  = @import("input");
const primitives = @import("primitives");
const mpt        = @import("mpt");

const Deserializer = struct {
    buf:   []const u8,
    pos:   usize,
    alloc: std.mem.Allocator,

    fn init(alloc: std.mem.Allocator, buf: []const u8) Deserializer {
        return .{ .buf = buf, .pos = 0, .alloc = alloc };
    }

    // ── Primitive readers ────────────────────────────────────────────────────

    fn readU8(self: *Deserializer) !u8 {
        if (self.pos >= self.buf.len) return error.UnexpectedEndOfInput;
        defer self.pos += 1;
        return self.buf[self.pos];
    }

    fn readU64(self: *Deserializer) !u64 {
        if (self.pos + 8 > self.buf.len) return error.UnexpectedEndOfInput;
        const v = std.mem.readInt(u64, self.buf[self.pos..][0..8], .big);
        self.pos += 8;
        return v;
    }

    fn readU128(self: *Deserializer) !u128 {
        if (self.pos + 16 > self.buf.len) return error.UnexpectedEndOfInput;
        const v = std.mem.readInt(u128, self.buf[self.pos..][0..16], .big);
        self.pos += 16;
        return v;
    }

    fn readU256(self: *Deserializer) !u256 {
        if (self.pos + 32 > self.buf.len) return error.UnexpectedEndOfInput;
        const v = std.mem.readInt(u256, self.buf[self.pos..][0..32], .big);
        self.pos += 32;
        return v;
    }

    fn readFixedBytes(self: *Deserializer, comptime N: usize) ![N]u8 {
        if (self.pos + N > self.buf.len) return error.UnexpectedEndOfInput;
        var out: [N]u8 = undefined;
        @memcpy(&out, self.buf[self.pos..][0..N]);
        self.pos += N;
        return out;
    }

    /// Zero-copy slice into the arena-owned buf.
    fn readByteSlice(self: *Deserializer) ![]const u8 {
        const len = try self.readU64();
        if (self.pos + len > self.buf.len) return error.UnexpectedEndOfInput;
        const slice = self.buf[self.pos..][0..len];
        self.pos += len;
        return slice;
    }

    // ── Skip helpers ─────────────────────────────────────────────────────────

    fn skipByteSlice(self: *Deserializer) !void {
        const len = try self.readU64();
        if (self.pos + len > self.buf.len) return error.UnexpectedEndOfInput;
        self.pos += len;
    }

    fn skipOptional(self: *Deserializer, comptime T: type) !void {
        const present = try self.readU8();
        if (present == 0) return;
        switch (T) {
            u64    => _ = try self.readU64(),
            [32]u8 => _ = try self.readFixedBytes(32),
            else   => @compileError("skipOptional: unsupported type"),
        }
    }

    fn skipHeader(self: *Deserializer) !void {
        _ = try self.readFixedBytes(32);  // parent_hash
        _ = try self.readFixedBytes(32);  // ommers_hash
        _ = try self.readFixedBytes(20);  // beneficiary
        _ = try self.readFixedBytes(32);  // state_root
        _ = try self.readFixedBytes(32);  // transactions_root
        _ = try self.readFixedBytes(32);  // receipts_root
        _ = try self.readFixedBytes(256); // logs_bloom
        _ = try self.readU256();           // difficulty
        _ = try self.readU64();            // number
        _ = try self.readU64();            // gas_limit
        _ = try self.readU64();            // gas_used
        _ = try self.readU64();            // timestamp
        try self.skipByteSlice();          // extra_data
        _ = try self.readFixedBytes(32);   // mix_hash
        _ = try self.readU64();            // nonce
        try self.skipOptional(u64);        // base_fee_per_gas
        try self.skipOptional([32]u8);     // withdrawals_root
        try self.skipOptional(u64);        // blob_gas_used
        try self.skipOptional(u64);        // excess_blob_gas
        try self.skipOptional([32]u8);     // parent_beacon_block_root
        try self.skipOptional([32]u8);     // requests_hash
    }

    fn readAccessListEntry(self: *Deserializer) !input_mod.AccessListEntry {
        const address  = try self.readFixedBytes(20);
        const num_keys = try self.readU64();
        const keys = try self.alloc.alloc(primitives.Hash, num_keys);
        for (0..num_keys) |i| keys[i] = try self.readFixedBytes(32);
        return .{ .address = address, .storage_keys = keys };
    }

    fn readTransaction(self: *Deserializer) !input_mod.Transaction {
        var tx = input_mod.Transaction{
            .tx_type              = try self.readU8(),
            .chain_id             = null,
            .nonce                = 0,
            .gas_price            = 0,
            .gas_priority_fee     = null,
            .gas_limit            = 0,
            .to                   = null,
            .value                = 0,
            .data                 = &.{},
            .access_list          = &.{},
            .blob_hashes          = &.{},
            .max_fee_per_blob_gas = 0,
            .v                    = 0,
            .r                    = 0,
            .s                    = 0,
        };

        if (try self.readU8() != 0) tx.chain_id       = try self.readU64();
        tx.nonce     = try self.readU64();
        tx.gas_price = try self.readU128();
        if (try self.readU8() != 0) tx.gas_priority_fee = try self.readU128();
        tx.gas_limit = try self.readU64();
        if (try self.readU8() != 0) tx.to = try self.readFixedBytes(20);
        tx.value = try self.readU256();
        tx.data  = try self.readByteSlice();

        const al_len = try self.readU64();
        if (al_len > 0) {
            const al = try self.alloc.alloc(input_mod.AccessListEntry, al_len);
            for (0..al_len) |i| al[i] = try self.readAccessListEntry();
            tx.access_list = al;
        }

        const bh_len = try self.readU64();
        if (bh_len > 0) {
            const bh = try self.alloc.alloc(primitives.Hash, bh_len);
            for (0..bh_len) |i| bh[i] = try self.readFixedBytes(32);
            tx.blob_hashes = bh;
        }

        tx.max_fee_per_blob_gas = try self.readU128();
        tx.v = try self.readU64();
        tx.r = try self.readU256();
        tx.s = try self.readU256();

        return tx;
    }

    fn skipWithdrawal(self: *Deserializer) !void {
        _ = try self.readU64();           // index
        _ = try self.readU64();           // validator_index
        _ = try self.readFixedBytes(20);  // address
        _ = try self.readU64();           // amount
    }

    fn readBlockHeader(self: *Deserializer) !input_mod.BlockHeader {
        var hdr: input_mod.BlockHeader = std.mem.zeroes(input_mod.BlockHeader);
        hdr.parent_hash              = try self.readFixedBytes(32);
        hdr.ommers_hash              = try self.readFixedBytes(32);
        hdr.beneficiary              = try self.readFixedBytes(20);
        hdr.state_root               = try self.readFixedBytes(32);
        hdr.transactions_root        = try self.readFixedBytes(32);
        hdr.receipts_root            = try self.readFixedBytes(32);
        hdr.logs_bloom               = try self.readFixedBytes(256);
        hdr.difficulty               = try self.readU256();
        hdr.number                   = try self.readU64();
        hdr.gas_limit                = try self.readU64();
        hdr.gas_used                 = try self.readU64();
        hdr.timestamp                = try self.readU64();
        hdr.extra_data               = try self.readByteSlice();
        hdr.mix_hash                 = try self.readFixedBytes(32);
        hdr.nonce                    = try self.readU64();
        if (try self.readU8() != 0) hdr.base_fee_per_gas         = try self.readU64();
        if (try self.readU8() != 0) hdr.withdrawals_root         = try self.readFixedBytes(32);
        if (try self.readU8() != 0) hdr.blob_gas_used            = try self.readU64();
        if (try self.readU8() != 0) hdr.excess_blob_gas          = try self.readU64();
        if (try self.readU8() != 0) hdr.parent_beacon_block_root = try self.readFixedBytes(32);
        if (try self.readU8() != 0) hdr.requests_hash            = try self.readFixedBytes(32);
        return hdr;
    }

    fn readExecutionWitness(self: *Deserializer) !input_mod.StateWitness {
        const state_count = try self.readU64();
        const nodes = try self.alloc.alloc([]const u8, state_count);
        for (0..state_count) |i| nodes[i] = try self.readByteSlice();

        const code_count = try self.readU64();
        const codes = try self.alloc.alloc([]const u8, code_count);
        for (0..code_count) |i| codes[i] = try self.readByteSlice();

        const key_count = try self.readU64();
        const keys = try self.alloc.alloc([]const u8, key_count);
        for (0..key_count) |i| keys[i] = try self.readByteSlice();

        const hdr_count = try self.readU64();
        const headers = try self.alloc.alloc([]const u8, hdr_count);
        for (0..hdr_count) |i| headers[i] = try self.readByteSlice();

        return input_mod.StateWitness{
            .state_root = @splat(0), // filled in by readStatelessInput
            .nodes      = nodes,
            .codes      = codes,
            .keys       = keys,
            .headers    = headers,
        };
    }

    fn readStatelessInput(self: *Deserializer) !input_mod.StatelessInput {
        const hdr = try self.readBlockHeader();

        const tx_count     = try self.readU64();
        const transactions = try self.alloc.alloc(input_mod.Transaction, tx_count);
        for (0..tx_count) |i| transactions[i] = try self.readTransaction();

        const ommer_count = try self.readU64();
        for (0..ommer_count) |_| try self.skipHeader();

        if (try self.readU8() != 0) {
            const w_count = try self.readU64();
            for (0..w_count) |_| try self.skipWithdrawal();
        }

        var witness = try self.readExecutionWitness();
        witness.state_root = findPreStateRoot(witness.headers, hdr.number) orelse hdr.state_root;

        return input_mod.StatelessInput{
            .block        = hdr,
            .transactions = transactions,
            .witness      = witness,
        };
    }
};

/// Scan witness headers for the parent block and return its stateRoot.
/// Returns null when block_number == 0 or no matching header is found.
/// Uses a minimal RLP decode that extracts only field #3 (stateRoot) and
/// field #8 (number) from each bare header RLP.
pub fn findPreStateRoot(headers: []const []const u8, block_number: u64) ?[32]u8 {
    if (block_number == 0) return null;
    const parent_number = block_number - 1;

    for (headers) |hdr_bytes| {
        const result = decodeMinimalHeader(hdr_bytes) catch continue;
        if (result.number == parent_number) return result.state_root;
    }
    return null;
}

const MinimalHeader = struct {
    number:     u64,
    state_root: [32]u8,
};

/// Decode block number (field 8) and state root (field 3) from a bare RLP header.
fn decodeMinimalHeader(raw: []const u8) !MinimalHeader {
    const hdr_r = mpt.rlp.decodeItem(raw) catch return error.InvalidHeader;
    const hdr_payload = switch (hdr_r.item) {
        .list  => |p| p,
        .bytes => return error.InvalidHeader,
    };

    var rest       = hdr_payload;
    var state_root = [_]u8{0} ** 32;
    var number:    u64 = 0;
    var i: usize = 0;

    while (i <= 8) : (i += 1) {
        if (rest.len == 0) return error.InvalidHeader;
        const r = mpt.rlp.decodeItem(rest) catch return error.InvalidHeader;
        switch (i) {
            3 => {
                const b = switch (r.item) { .bytes => |bts| bts, .list => return error.InvalidHeader };
                if (b.len != 32) return error.InvalidHeader;
                @memcpy(&state_root, b);
            },
            8 => {
                const b = switch (r.item) { .bytes => |bts| bts, .list => return error.InvalidHeader };
                if (b.len > 8) return error.InvalidHeader;
                for (b) |byte| number = (number << 8) | byte;
            },
            else => {},
        }
        rest = rest[r.consumed..];
    }

    return MinimalHeader{ .number = number, .state_root = state_root };
}

/// Deserialize a StatelessInput from a raw byte slice (zevm-zisk binary format).
pub fn fromBytes(allocator: std.mem.Allocator, data: []const u8) !input_mod.StatelessInput {
    var d = Deserializer.init(allocator, data);
    return d.readStatelessInput();
}
