/// Zisk precompile implementations.
///
/// This module is the "precompile_implementations" injection point for the
/// Zisk zkVM build.  BN254 add/mul/pairing are dispatched to Zisk hardware
/// circuits via eip196.zig / zisk_circuits.zig.
///
/// ECRECOVER, KZG point evaluation, BLS12-381, and P256Verify do not yet
/// have Zisk hardware circuits; they return an error result (OutOfGas) so
/// that callers fail gracefully rather than silently returning wrong answers.
/// TODO: wire Zisk accelerators for ECRECOVER, KZG, and BLS12-381.
///
/// Injected into zevm's precompile module via:
///   precompile_module.addImport("precompile_implementations", zisk_impls_module)
/// in zevm-stateless-zisk/build.zig.

const T = @import("precompile_types");
const alloc_mod = @import("zevm_allocator");
// Access eip196 through the 'zisk' named module so that eip196.zig (and its
// transitive imports like zisk_circuits.zig) belong to exactly one module.
const eip196 = @import("zisk").eip196;

// ── Input/output sizes ────────────────────────────────────────────────────────

const G1_LEN: usize = 64; // 2 × 32-byte Fq coordinates
const ADD_INPUT_LEN: usize = 128; // two G1 points
const MUL_INPUT_LEN: usize = 96; // G1 point + 32-byte scalar
const PAIR_ELEMENT_LEN: usize = 192; // G1 (64) + G2 (128)

// ── Gas costs ─────────────────────────────────────────────────────────────────

const BYZANTIUM_ADD_GAS: u64 = 500;
const ISTANBUL_ADD_GAS: u64 = 150;
const BYZANTIUM_MUL_GAS: u64 = 40_000;
const ISTANBUL_MUL_GAS: u64 = 6_000;
const BYZANTIUM_PAIRING_BASE: u64 = 100_000;
const BYZANTIUM_PAIRING_PER_POINT: u64 = 80_000;
const ISTANBUL_PAIRING_BASE: u64 = 45_000;
const ISTANBUL_PAIRING_PER_POINT: u64 = 34_000;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn rightPad(comptime len: usize, input: []const u8) [len]u8 {
    var padded = [_]u8{0} ** len;
    const n = @min(input.len, len);
    @memcpy(padded[0..n], input[0..n]);
    return padded;
}

// ── BN254 Add ─────────────────────────────────────────────────────────────────

fn bn254AddRun(input: []const u8, gas_cost: u64, gas_limit: u64) T.PrecompileResult {
    if (gas_cost > gas_limit)
        return T.PrecompileResult{ .err = T.PrecompileError.OutOfGas };

    const padded = rightPad(ADD_INPUT_LEN, input);
    const p1: [G1_LEN]u8 = padded[0..G1_LEN].*;
    const p2: [G1_LEN]u8 = padded[G1_LEN..].*;

    var out: [G1_LEN]u8 = undefined;
    eip196.ecAdd(&p1, &p2, &out);

    const heap_out = alloc_mod.get().dupe(u8, &out) catch
        return T.PrecompileResult{ .err = T.PrecompileError.OutOfGas };
    return T.PrecompileResult{ .success = T.PrecompileOutput.new(gas_cost, heap_out) };
}

fn bn254AddByzantium(input: []const u8, gas_limit: u64) T.PrecompileResult {
    return bn254AddRun(input, BYZANTIUM_ADD_GAS, gas_limit);
}
fn bn254AddIstanbul(input: []const u8, gas_limit: u64) T.PrecompileResult {
    return bn254AddRun(input, ISTANBUL_ADD_GAS, gas_limit);
}

// ── BN254 Mul ─────────────────────────────────────────────────────────────────

fn bn254MulRun(input: []const u8, gas_cost: u64, gas_limit: u64) T.PrecompileResult {
    if (gas_cost > gas_limit)
        return T.PrecompileResult{ .err = T.PrecompileError.OutOfGas };

    const padded = rightPad(MUL_INPUT_LEN, input);
    const pt: [G1_LEN]u8 = padded[0..G1_LEN].*;
    const sc: [32]u8 = padded[G1_LEN..MUL_INPUT_LEN].*;

    var out: [G1_LEN]u8 = undefined;
    eip196.ecMul(&pt, &sc, &out);

    const heap_out = alloc_mod.get().dupe(u8, &out) catch
        return T.PrecompileResult{ .err = T.PrecompileError.OutOfGas };
    return T.PrecompileResult{ .success = T.PrecompileOutput.new(gas_cost, heap_out) };
}

fn bn254MulByzantium(input: []const u8, gas_limit: u64) T.PrecompileResult {
    return bn254MulRun(input, BYZANTIUM_MUL_GAS, gas_limit);
}
fn bn254MulIstanbul(input: []const u8, gas_limit: u64) T.PrecompileResult {
    return bn254MulRun(input, ISTANBUL_MUL_GAS, gas_limit);
}

// ── BN254 Pairing ─────────────────────────────────────────────────────────────

fn bn254PairingRun(
    input: []const u8,
    base_gas: u64,
    per_point_gas: u64,
    gas_limit: u64,
) T.PrecompileResult {
    if (input.len % PAIR_ELEMENT_LEN != 0)
        return T.PrecompileResult{ .err = T.PrecompileError.Bn254PairLength };

    const n_pairs = input.len / PAIR_ELEMENT_LEN;
    const gas_used = @as(u64, n_pairs) * per_point_gas + base_gas;
    if (gas_used > gas_limit)
        return T.PrecompileResult{ .err = T.PrecompileError.OutOfGas };

    var result: [32]u8 = [_]u8{0} ** 32;
    eip196.ecPairing(input, &result, alloc_mod.get()) catch
        return T.PrecompileResult{ .err = T.PrecompileError.Bn254PairLength };

    const heap_out = alloc_mod.get().dupe(u8, &result) catch
        return T.PrecompileResult{ .err = T.PrecompileError.OutOfGas };
    return T.PrecompileResult{ .success = T.PrecompileOutput.new(gas_used, heap_out) };
}

fn bn254PairingByzantium(input: []const u8, gas_limit: u64) T.PrecompileResult {
    return bn254PairingRun(input, BYZANTIUM_PAIRING_BASE, BYZANTIUM_PAIRING_PER_POINT, gas_limit);
}
fn bn254PairingIstanbul(input: []const u8, gas_limit: u64) T.PrecompileResult {
    return bn254PairingRun(input, ISTANBUL_PAIRING_BASE, ISTANBUL_PAIRING_PER_POINT, gas_limit);
}

// ── Stubs for unimplemented precompiles ───────────────────────────────────────
// These precompiles lack Zisk hardware circuits.  Return OutOfGas so callers
// fail explicitly rather than returning silent wrong results.
// TODO: replace each stub with a Zisk accelerator implementation.

fn ecrecoverStub(_: []const u8, _: u64) T.PrecompileResult {
    return T.PrecompileResult{ .err = T.PrecompileError.OutOfGas };
}

fn kzgStub(_: []const u8, _: u64) T.PrecompileResult {
    return T.PrecompileResult{ .err = T.PrecompileError.OutOfGas };
}

fn bls12Stub(_: []const u8, _: u64) T.PrecompileResult {
    return T.PrecompileResult{ .err = T.PrecompileError.OutOfGas };
}

fn p256verifyStub(_: []const u8, _: u64) T.PrecompileResult {
    return T.PrecompileResult{ .err = T.PrecompileError.OutOfGas };
}

// ── Implementation table ──────────────────────────────────────────────────────
// Required (non-optional) function pointers for every precompile.

// Homestead
pub const ecrecover: T.PrecompileFn = ecrecoverStub;

// Byzantium
pub const bn254_add_byzantium:     T.PrecompileFn = bn254AddByzantium;
pub const bn254_mul_byzantium:     T.PrecompileFn = bn254MulByzantium;
pub const bn254_pairing_byzantium: T.PrecompileFn = bn254PairingByzantium;

// Istanbul
pub const bn254_add_istanbul:     T.PrecompileFn = bn254AddIstanbul;
pub const bn254_mul_istanbul:     T.PrecompileFn = bn254MulIstanbul;
pub const bn254_pairing_istanbul: T.PrecompileFn = bn254PairingIstanbul;

// Cancun
pub const kzg_point_evaluation: T.PrecompileFn = kzgStub;

// Prague / BLS12-381
pub const bls12_g1_add:        T.PrecompileFn = bls12Stub;
pub const bls12_g1_msm:        T.PrecompileFn = bls12Stub;
pub const bls12_g2_add:        T.PrecompileFn = bls12Stub;
pub const bls12_g2_msm:        T.PrecompileFn = bls12Stub;
pub const bls12_pairing:       T.PrecompileFn = bls12Stub;
pub const bls12_map_fp_to_g1:  T.PrecompileFn = bls12Stub;
pub const bls12_map_fp2_to_g2: T.PrecompileFn = bls12Stub;

// Osaka
pub const p256verify:       T.PrecompileFn = p256verifyStub;
pub const p256verify_osaka: T.PrecompileFn = p256verifyStub;
