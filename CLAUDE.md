# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

A Zisk zkVM guest binary that executes Ethereum blocks statelessly. It compiles to
`riscv64-freestanding-none` (rv64im) with no libc, no OS, and no native crypto libraries.
The prover runs the binary and attests to the execution result: given pre-state root X and
these transactions, execution produces post-state root Y with receipts root Z.

Local path dependencies:
- `../zevm` — EVM implementation in Zig (crypto libs disabled for this build)
- `../zevm-stateless` — stateless witness types, MPT proof verification, WitnessDatabase

## Build commands

```sh
zig build                        # Build guest ELF (riscv64-freestanding-none)
zig build -Doptimize=ReleaseFast # Release build
zig build run                    # Run via ziskemu emulator (must be in PATH)
```

Output: `zig-out/bin/zevm-stateless-zisk` (statically linked RISC-V ELF, no dynamic deps).

To verify changes don't break the native zevm tests:
```sh
cd ../zevm && zig build test
```

## Key architectural constraints

### Freestanding target — things that cannot be used

- `std.heap.GeneralPurposeAllocator` — triggers `page_size_max` compile error for freestanding.
  Use `alloc_mod.get()` from `@import("zevm_allocator")` instead.
- `std.heap.c_allocator` — requires libc
- `std.debug.print` — requires OS; use `main.uartWrite()` for diagnostic output
- `std.process.exit` — use `zkExit()` or return errors
- `@cImport` / C libraries — no FFI in freestanding
- `std.Thread.Mutex` — no OS threading
- Any `std.fs`, `std.net`, stdin/stdout I/O

### Allocator

All heap allocation goes through the Zisk bump allocator:

```zig
// In guest code:
const alloc_mod = @import("zevm_allocator");
const allocator = alloc_mod.get();

// At program start (main.zig already does this):
var zisk_alloc = zisk.ZiskAllocator.init();
```

The bump allocator never frees — it's a single arena for the lifetime of the guest execution.
`alloc_mod.get()` returns the singleton allocator initialized in `main()`.

### Zig module ownership

Each `.zig` source file can belong to exactly one Zig module. The compiler enforces this.
Violations produce: `error: file exists in modules 'A' and 'B'`.

Rules for this repo:
- Files in `src/zisk/` belong to one of the `zisk`, `zevm_allocator`, or
  `precompile_implementations` modules — never directly imported by other modules.
- The `precompile_implementations` module (`precompile_overrides.zig`) owns its own source
  files. Do not `@import("secp256k1.zig")` or similar C-dep files from any other module.
- Test helper functions in zevm modules (database, context, etc.) must live in `*_test.zig`
  files, not inside `pub const testing = struct {}` blocks in production source. The latter
  are eagerly analyzed even if never called, pulling in GPA and causing freestanding errors.

## Precompile injection pattern

zevm's precompile module has an injection point: whatever module is wired as
`precompile_implementations` provides the concrete precompile functions. This repo supplies
`src/zisk/precompile_overrides.zig` as that module.

`build.zig` wires it:
```zig
precompile.addImport("precompile_implementations", zisk_overrides_module);
```

`precompile_overrides.zig` must export a `T.PrecompileFn` (non-optional function pointer) for
every precompile name defined in `zevm/src/precompile/native_impls.zig`. If a Zisk hardware
circuit doesn't exist yet, export a stub that returns `OutOfGas`.

Currently wired:
- BN254 add/mul/pairing → Zisk hardware circuits via `eip196.zig`
- Everything else → `OutOfGas` stubs (ECRECOVER, KZG, BLS12-381, P256Verify)

## Module graph (build.zig)

```
main.zig  (root)
  ├── zisk          src/zisk/main.zig
  ├── execute       src/execute.zig
  ├── zkvm_io       src/zkvm_io.zig
  ├── deserialize   src/deserialize.zig
  ├── input         zevm-stateless/src/input.zig
  ├── output        zevm-stateless/src/output.zig
  ├── mpt           zevm-stateless/src/mpt/main.zig
  ├── db            zevm-stateless/src/db/main.zig
  └── (zevm modules via zevm_dep)
        primitives, bytecode, state, database, context,
        interpreter, precompile, handler, inspector

zevm_allocator  src/zisk/zevm_allocator.zig
  └── zisk

precompile_implementations  src/zisk/precompile_overrides.zig
  ├── precompile_types  (from zevm)
  ├── zevm_allocator
  └── zisk
```

zevm modules that allocate heap memory have `zevm_allocator` injected so they use the
Zisk bump allocator:  bytecode, state, context, interpreter, precompile, handler.

## Important files

| File | Role |
|---|---|
| `src/main.zig` | `_start` entry, UART, zkExit, panic handler, top-level I/O |
| `src/execute.zig` | 3-phase block execution pipeline (MPT verify → WitnessDB → EVM) |
| `src/deserialize.zig` | `fromBytes()` — deserializes `StatelessInput` from a byte slice |
| `src/zkvm_io.zig` | Memory-mapped input/output region helpers |
| `src/zisk/allocator.zig` | `ZiskAllocator` bump allocator over the linker heap |
| `src/zisk/zevm_allocator.zig` | Adapter: exposes `get()` returning the Zisk allocator |
| `src/zisk/precompile_overrides.zig` | Precompile implementations for the zkVM |
| `src/zisk/eip196.zig` | BN254 ecAdd / ecMul / ecPairing via Zisk CSR circuits |
| `src/zisk/zisk_circuits.zig` | Raw CSR bindings for all Zisk hardware accelerators |
| `zisk.ld` | Linker script: ROM 0x80000000, RAM 0xa0020000 |
| `build.zig` | Full module graph, target config (rv64im freestanding) |

## Adding a Zisk hardware accelerator for a precompile

1. Add the CSR binding to `src/zisk/zisk_circuits.zig` if not already there.
2. Implement the precompile logic in a new file (e.g., `src/zisk/ecrecover.zig`) using
   the circuit CSR.
3. Export it from `src/zisk/main.zig`.
4. Wire it in `src/zisk/precompile_overrides.zig` — replace the `OutOfGas` stub with the
   real implementation, using the `T.PrecompileFn` signature:
   `pub const ecrecover: T.PrecompileFn = myImpl;`
5. `zig build` — no build.zig changes needed unless a new source file requires a new module.

## Common pitfalls

- **Do not add `std.heap.GeneralPurposeAllocator` to any file reachable from freestanding
  code.** Even in a `pub fn` that's never called, if the function is inside a `pub const`
  struct that's part of a module, it gets analyzed and fails for freestanding targets.

- **Do not `@import` a relative path (e.g. `@import("secp256k1.zig")`) from a file that
  belongs to the `precompile` module.** Those files are owned by `precompile_implementations`.
  Use `@import("precompile_implementations").ecrecover` etc. instead.

- **The `zisk.ld` linker script is required.** `exe.setLinkerScript(b.path("zisk.ld"))` must
  remain in `build.zig`. Without it the code model and memory layout are wrong.

- **Code model must be `.medium`.** `exe.root_module.code_model = .medium;` is required for
  the rv64im target to reach addresses in ROM/RAM correctly.

- **`defer _ = gpa.deinit()` is incorrect when the GPA-allocated memory outlives the scope.**
  `TxEnv` and `TxEnvBuilder` previously had this bug — allocating `AccessList` with a GPA
  then immediately destroying it. Always use `alloc_mod.get()` for any allocation that lives
  beyond the allocating scope.

## zevm dependency relationship

This repo imports zevm as a path dependency and rebuilds each module with freestanding-safe
options. It does NOT use `zevm_dep.module("precompile")` directly — it uses
`zevm_dep.module("precompile")` from the dep but overrides its `precompile_implementations`
import to inject `precompile_overrides.zig`. Similarly, `zevm_allocator` for all zevm modules
is replaced with the Zisk bump allocator.

If zevm changes its module interface (adds a new named import requirement, renames a pub
export), `build.zig` and `precompile_overrides.zig` may need updating.
