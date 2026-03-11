/// Keccak-256 using the Zisk keccakf hardware circuit (CSR 0x800).
///
/// Sponge parameters for Keccak-256 (EVM variant, not SHA3-256):
///   rate     = 136 bytes  (1088 bits)
///   capacity =  64 bytes  ( 512 bits)
///   state    = 200 bytes  (1600 bits)
///   output   =  32 bytes  ( 256 bits)
///   padding  = multi-rate: append 0x01 ... 0x80 (Keccak, not SHA3)
const zisk = @import("zisk");

const RATE: usize = 136;

pub fn keccak256(data: []const u8) [32]u8 {
    var state: [200]u8 = [_]u8{0} ** 200;

    // ── Absorb full-rate blocks ───────────────────────────────────────────────
    var offset: usize = 0;
    while (offset + RATE <= data.len) : (offset += RATE) {
        for (0..RATE) |i| state[i] ^= data[offset + i];
        zisk.keccakf(&state);
    }

    // ── Absorb final partial block + Keccak padding ───────────────────────────
    const tail = data.len - offset;
    for (0..tail) |i| state[i] ^= data[offset + i];
    state[tail]      ^= 0x01;   // Keccak domain separation (0x01, not SHA3 0x06)
    state[RATE - 1]  ^= 0x80;   // final padding bit
    zisk.keccakf(&state);

    // ── Squeeze 32 bytes ──────────────────────────────────────────────────────
    var out: [32]u8 = undefined;
    @memcpy(&out, state[0..32]);
    return out;
}
