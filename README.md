# zevm-stateless-zisk

A [Zisk](https://github.com/0xPolygonHermez/zisk) zkVM guest program that executes Ethereum blocks
statelessly and commits a proof output — without any OS, libc, or native crypto libraries.

Built on:
- **[zevm](../zevm)** — Ethereum Virtual Machine in Zig
- **[zevm-stateless](../zevm-stateless)** — stateless witness types, MPT verification, and deserialization

## Purpose

This guest binary runs inside the Zisk zkVM prover. Given a `StatelessInput` (pre-state witness +
block transactions), it:

1. **Verifies MPT proofs** — confirms the supplied account/storage witnesses against the
   pre-execution state root
2. **Builds a WitnessDatabase** — constructs an in-memory EVM state backed by the proven witness
3. **Executes the block** — runs all transactions through zevm and accumulates receipts
4. **Commits outputs** — writes `pre_state_root | post_state_root | receipts_root` to the zkVM
   output region for the prover to attest

The result is a provable claim: given pre-state root X and these transactions, execution produces
post-state root Y with receipts root Z.

## Architecture

```
src/
  main.zig                  Entry point: _start → _start_main → main()
                            Reads input from zkVM I/O region, calls execute.executeBlock,
                            writes output roots, handles UART logging and panic.

  execute.zig               Stateless block execution pipeline (3 phases above).

  deserialize.zig           Binary deserializer for StatelessInput — reads from a byte slice
                            rather than stdin (freestanding-compatible).

  zkvm_io.zig               Memory-mapped I/O helpers for Zisk input/output regions.

  zisk/
    main.zig                Zisk runtime module — re-exports allocators and hardware circuits.
    allocator.zig           ZiskAllocator: bump allocator over the linker-provided heap region.
    zevm_allocator.zig      Adapter that wires ZiskAllocator into zevm's allocator hook.
    precompile_overrides.zig  Precompile injection point for the Zisk build:
                              - BN254 add/mul/pairing → Zisk hardware circuits (eip196.zig)
                              - ECRECOVER, KZG, BLS12-381, P256Verify → OutOfGas stubs
    eip196.zig              BN254 elliptic curve operations using Zisk hardware circuits.
    bn254_pairing.zig       Pure-Zig BN254 pairing implementation for the zkVM.
    zisk_circuits.zig       RISC-V CSR bindings for Zisk hardware accelerators
                            (keccak, SHA-256, secp256k1, BN254, BLS12-381, arith256).

zisk.ld                     Linker script: ROM at 0x80000000 (128 MB), RAM at 0xa0020000 (~512 MB).
```

## Target

The binary targets `riscv64-freestanding-none` with the `rv64im` instruction set (integer + multiply
only — no atomics, floats, compressed instructions). This matches the Zisk VM's RISC-V dialect.

No libc. No OS. No native crypto libraries. All cryptographic operations either use the Zisk
hardware circuit interface (BN254) or pure-Zig implementations.

## Dependencies

| Dependency | Source | Purpose |
|---|---|---|
| `zevm` | `../zevm` (path dep) | EVM implementation — all native crypto libs disabled |
| `zevm-stateless` | `../zevm-stateless` (path dep) | Input/output types, MPT, WitnessDatabase |
| Zig | 0.15.1+ | Toolchain |
| `ziskemu` | PATH (optional) | Emulator for local `zig build run` |

No package manager beyond Zig's built-in fetch. Both dependencies are local path references.

## Building

```sh
# Build the guest ELF (outputs to zig-out/bin/zevm-stateless-zisk)
zig build

# Build with release optimization
zig build -Doptimize=ReleaseFast

# Run under the Zisk emulator (requires ziskemu in PATH)
zig build run
```

The ELF is a statically linked RISC-V binary with no dynamic dependencies. It can be loaded
directly into the Zisk prover or emulated with `ziskemu`.

## Precompile Design

zevm's precompile module accepts an injected `precompile_implementations` module at build time.
This repo supplies `src/zisk/precompile_overrides.zig` as that module, which:

- Routes **BN254 ecAdd / ecMul / ecPairing** through Zisk hardware circuits — the zkVM proves
  these operations natively, making them cheap to verify.
- Returns **OutOfGas** for ECRECOVER, KZG point evaluation, BLS12-381, and P256Verify — these
  lack Zisk hardware circuits and will be wired to accelerators as they become available.

This injection pattern means no C libraries or OS-dependent code ever enters the freestanding
compilation graph.

## Memory Layout

| Region | Address | Size | Contents |
|---|---|---|---|
| ROM | `0x80000000` | 128 MB | Code and read-only data |
| System | `0xa0000000` | 64 KB | Zisk registers, UART (`0xa0000200`), CSRs |
| Output | `0xa0010000` | 64 KB | zkVM output region (proof commitments) |
| Stack | `0xa0020000` | 1 MB | Stack (grows up from RAM base) |
| Heap | `0xa0120000` | ~511 MB | ZiskAllocator bump heap |

Input data is read from the Zisk input region via `zkvm_io.read_input_slice()`.
Output roots are written to the output region via `zkvm_io.write_output_slice()`.

## Status

| Feature | Status |
|---|---|
| MPT proof verification | Working |
| WitnessDatabase construction | Working |
| EVM block execution (zevm) | Working |
| BN254 via Zisk circuits | Working |
| Post-execution state root rebuild | TODO |
| ECRECOVER accelerator | TODO |
| KZG point evaluation accelerator | TODO |
| BLS12-381 accelerators | TODO |
