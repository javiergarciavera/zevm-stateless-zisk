/// Freestanding secp256k1 stub for the Zisk zkVM target.
///
/// Hardware-accelerated secp256k1 (ecrecover/sign) is not yet implemented
/// for Zisk.  getContext() returns null so that all signing/recovery calls
/// fall back gracefully — callers check for null before dereferencing.
///
/// TODO: replace with a Zisk CSR-backed implementation once the secp256k1
///       hardware circuit is available.

pub const Secp256k1 = struct {
    pub fn sign(_: Secp256k1, _: [32]u8, _: [32]u8) ?struct { sig: [64]u8, recid: u8 } {
        return null;
    }

    pub fn ecrecover(_: Secp256k1, _: [32]u8, _: [64]u8, _: u8) ?[20]u8 {
        return null;
    }
};

pub fn getContext() ?Secp256k1 {
    return null;
}
