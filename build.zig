const std = @import("std");

pub fn build(b: *std.Build) void {
    // Force RISC-V 64-bit freestanding target for Zisk zkVM
    // rv64im baseline: no atomics, no float, no compressed instructions
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv64,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
        .cpu_features_add = std.Target.riscv.featureSet(&.{.m}),
        .cpu_features_sub = std.Target.riscv.featureSet(&.{ .a, .c, .d, .f, .zicsr, .zaamo, .zalrsc }),
        .os_tag = .freestanding,
        .abi = .none,
    });

    const optimize = b.standardOptimizeOption(.{});

    // Build options — all native crypto libraries disabled for freestanding zkVM target
    const lib_options = b.addOptions();
    lib_options.addOption(bool, "enable_blst", false);
    lib_options.addOption(bool, "enable_mcl", false);
    lib_options.addOption(bool, "enable_secp256k1", false);
    lib_options.addOption(bool, "enable_openssl", false);
    const lib_options_module = lib_options.createModule();

    // zevm dependency — imported directly so we control enable_blst/enable_mcl.
    // zevm-stateless's own build.zig hardcodes enable_blst=true for its native
    // exe, so we bypass that by importing zevm separately here.
    const zevm_dep = b.dependency("zevm", .{
        .target = target,
        .optimize = optimize,
    });

    const primitives = zevm_dep.module("primitives");
    const bytecode = zevm_dep.module("bytecode");
    const state = zevm_dep.module("state");
    const database = zevm_dep.module("database");
    const context = zevm_dep.module("context");
    const interpreter = zevm_dep.module("interpreter");
    const precompile = zevm_dep.module("precompile");
    const handler = zevm_dep.module("handler");
    const inspector = zevm_dep.module("inspector");

    // Attach freestanding-compatible build options to precompile
    precompile.addImport("build_options", lib_options_module);

    // zevm-stateless path dependency — used only for source file paths.
    // We re-create each module ourselves (wired to our zevm dep) rather than
    // calling dep.module() which would pull in the native-lib-linked versions.
    const zs_dep = b.dependency("zevm_stateless", .{});

    const input_mod = b.addModule("input", .{
        .root_source_file = zs_dep.path("src/input.zig"),
        .target = target,
        .optimize = optimize,
    });
    input_mod.addImport("primitives", primitives);

    const output_mod = b.addModule("output", .{
        .root_source_file = zs_dep.path("src/output.zig"),
        .target = target,
        .optimize = optimize,
    });
    output_mod.addImport("primitives", primitives);

    const mpt_nibbles_mod = b.createModule(.{
        .root_source_file = zs_dep.path("src/mpt/nibbles.zig"),
        .target = target,
        .optimize = optimize,
    });

    const mpt_mod = b.addModule("mpt", .{
        .root_source_file = zs_dep.path("src/mpt/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    mpt_mod.addImport("primitives", primitives);
    mpt_mod.addImport("input", input_mod);
    mpt_mod.addImport("mpt_nibbles", mpt_nibbles_mod);
    // keccak_impl wired below, after zisk_mod is defined

    const mpt_builder_mod = b.createModule(.{
        .root_source_file = zs_dep.path("src/mpt/builder.zig"),
        .target = target,
        .optimize = optimize,
    });
    mpt_builder_mod.addImport("mpt_nibbles", mpt_nibbles_mod);

    const db_mod = b.addModule("db", .{
        .root_source_file = zs_dep.path("src/db/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    db_mod.addImport("primitives", primitives);
    db_mod.addImport("state", state);
    db_mod.addImport("bytecode", bytecode);
    db_mod.addImport("mpt", mpt_mod);
    db_mod.addImport("input", input_mod);

    // Zisk zkVM runtime support module (local)
    const zisk_mod = b.addModule("zisk", .{
        .root_source_file = b.path("src/zisk/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    zisk_mod.addImport("primitives", primitives);

    // Zisk keccak_impl — hardware-accelerated Keccak-256 sponge via CSR 0x800.
    // Overrides the default pure-Zig std.crypto implementation in zevm-stateless.
    const keccak_impl_mod = b.addModule("keccak_impl", .{
        .root_source_file = b.path("src/zisk/keccak_impl.zig"),
        .target = target,
        .optimize = optimize,
    });
    keccak_impl_mod.addImport("zisk", zisk_mod);
    mpt_mod.addImport("keccak_impl", keccak_impl_mod);

    // ── Zisk bump allocator ───────────────────────────────────────────────────
    // Replace zevm's default c_allocator shim with the Zisk bump allocator in
    // every zevm module that allocates heap memory.
    // zevm_allocator.zig imports ZiskAllocator via the 'zisk' named module so
    // that allocator.zig belongs to exactly one module (the 'zisk' module).
    const zisk_allocator_module = b.addModule("zevm_allocator", .{
        .root_source_file = b.path("src/zisk/zevm_allocator.zig"),
        .target = target,
        .optimize = optimize,
    });
    zisk_allocator_module.addImport("zisk", zisk_mod);

    bytecode.addImport("zevm_allocator", zisk_allocator_module);
    state.addImport("zevm_allocator", zisk_allocator_module);
    context.addImport("zevm_allocator", zisk_allocator_module);
    interpreter.addImport("zevm_allocator", zisk_allocator_module);
    precompile.addImport("zevm_allocator", zisk_allocator_module);
    handler.addImport("zevm_allocator", zisk_allocator_module);

    // ── Zisk precompile overrides ─────────────────────────────────────────────
    // BN254 add/mul/pairing are dispatched to Zisk hardware circuits.
    // All other precompiles remain at their zevm defaults (null override).
    const precompile_types = zevm_dep.module("precompile_types");
    const zisk_overrides_module = b.addModule("precompile_overrides", .{
        .root_source_file = b.path("src/zisk/precompile_overrides.zig"),
        .target = target,
        .optimize = optimize,
    });
    zisk_overrides_module.addImport("precompile_types", precompile_types);
    zisk_overrides_module.addImport("zevm_allocator", zisk_allocator_module);
    zisk_overrides_module.addImport("zisk", zisk_mod);

    precompile.addImport("precompile_implementations", zisk_overrides_module);

    // ── Executor sub-modules ─────────────────────────────────────────────────
    // Mirrors the pattern in zevm-stateless/build.zig, but using the Zisk
    // bump allocator and freestanding secp256k1 stub.

    const executor_types_mod = b.createModule(.{
        .root_source_file = zs_dep.path("src/executor/types.zig"),
        .target = target,
        .optimize = optimize,
    });

    const executor_rlp_encode_mod = b.createModule(.{
        .root_source_file = zs_dep.path("src/executor/rlp_encode.zig"),
        .target = target,
        .optimize = optimize,
    });

    const executor_fork_mod = b.createModule(.{
        .root_source_file = zs_dep.path("src/executor/fork.zig"),
        .target = target,
        .optimize = optimize,
    });
    executor_fork_mod.addImport("primitives", primitives);

    // rlp_decode: raw Ethereum RLP → input types; needed by tx_decode
    const rlp_decode_mod = b.createModule(.{
        .root_source_file = zs_dep.path("src/rlp_decode.zig"),
        .target = target,
        .optimize = optimize,
    });
    rlp_decode_mod.addImport("input", input_mod);
    rlp_decode_mod.addImport("primitives", primitives);
    rlp_decode_mod.addImport("mpt", mpt_mod);

    const executor_tx_decode_mod = b.createModule(.{
        .root_source_file = zs_dep.path("src/executor/tx_decode.zig"),
        .target = target,
        .optimize = optimize,
    });
    executor_tx_decode_mod.addImport("executor_types", executor_types_mod);
    executor_tx_decode_mod.addImport("input", input_mod);
    executor_tx_decode_mod.addImport("rlp_decode", rlp_decode_mod);

    // secp256k1 — hardware-accelerated ecrecover via Zisk CSR circuits
    const secp256k1_mod = b.createModule(.{
        .root_source_file = b.path("src/zisk/secp256k1.zig"),
        .target = target,
        .optimize = optimize,
    });
    secp256k1_mod.addImport("zisk", zisk_mod);

    const executor_output_mod = b.createModule(.{
        .root_source_file = zs_dep.path("src/executor/output.zig"),
        .target = target,
        .optimize = optimize,
    });
    executor_output_mod.addImport("executor_types", executor_types_mod);
    executor_output_mod.addImport("executor_rlp_encode", executor_rlp_encode_mod);
    executor_output_mod.addImport("mpt_builder", mpt_builder_mod);
    executor_output_mod.addImport("mpt", mpt_mod);

    const executor_transition_mod = b.createModule(.{
        .root_source_file = zs_dep.path("src/executor/transition.zig"),
        .target = target,
        .optimize = optimize,
    });
    executor_transition_mod.addImport("executor_types", executor_types_mod);
    executor_transition_mod.addImport("executor_rlp_encode", executor_rlp_encode_mod);
    executor_transition_mod.addImport("executor_output", executor_output_mod);
    executor_transition_mod.addImport("primitives", primitives);
    executor_transition_mod.addImport("state", state);
    executor_transition_mod.addImport("bytecode", bytecode);
    executor_transition_mod.addImport("database", database);
    executor_transition_mod.addImport("context", context);
    executor_transition_mod.addImport("handler", handler);
    executor_transition_mod.addImport("precompile", precompile);
    executor_transition_mod.addImport("secp256k1_wrapper", secp256k1_mod);
    // executor_allocator — inject the Zisk bump allocator so transition.zig
    // uses it instead of std.heap.c_allocator (unavailable in freestanding).
    executor_transition_mod.addImport("executor_allocator", zisk_allocator_module);

    // Executor module — the zevm-stateless three-phase execution pipeline.
    // Re-created here (rather than using zs_dep.module()) so it picks up the
    // Zisk-specific mpt (hardware keccak) and zevm modules (bump allocator,
    // precompile overrides) that are already wired above.
    const executor_mod = b.addModule("executor", .{
        .root_source_file = zs_dep.path("src/executor/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    executor_mod.addImport("primitives", primitives);
    executor_mod.addImport("context", context);
    executor_mod.addImport("mpt", mpt_mod);
    executor_mod.addImport("input", input_mod);
    executor_mod.addImport("output", output_mod);
    executor_mod.addImport("executor_types", executor_types_mod);
    executor_mod.addImport("executor_output", executor_output_mod);
    executor_mod.addImport("executor_transition", executor_transition_mod);
    executor_mod.addImport("executor_fork", executor_fork_mod);
    executor_mod.addImport("executor_tx_decode", executor_tx_decode_mod);

    // Local deserializer module — adapted from zevm-stateless's deserialize.zig
    // but works from a byte slice instead of stdin (freestanding-compatible).
    // TODO: upstream a pub fromBytes() into zevm-stateless/src/deserialize.zig
    //       and remove this local copy once that lands.
    const deserialize_mod = b.addModule("deserialize", .{
        .root_source_file = b.path("src/deserialize.zig"),
        .target = target,
        .optimize = optimize,
    });
    deserialize_mod.addImport("input", input_mod);
    deserialize_mod.addImport("primitives", primitives);
    deserialize_mod.addImport("mpt", mpt_mod);
    deserialize_mod.addImport("rlp_decode", rlp_decode_mod);

    // Main Zisk guest executable
    const exe = b.addExecutable(.{
        .name = "zevm-stateless-zisk",
        .root_module = b.addModule("zevm-stateless-zisk-main", .{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Zisk memory layout and entry point
    exe.setLinkerScript(b.path("zisk.ld"));
    exe.root_module.code_model = .medium;

    exe.root_module.addImport("zisk", zisk_mod);
    exe.root_module.addImport("primitives", primitives);
    exe.root_module.addImport("bytecode", bytecode);
    exe.root_module.addImport("state", state);
    exe.root_module.addImport("database", database);
    exe.root_module.addImport("context", context);
    exe.root_module.addImport("interpreter", interpreter);
    exe.root_module.addImport("precompile", precompile);
    exe.root_module.addImport("handler", handler);
    exe.root_module.addImport("inspector", inspector);
    exe.root_module.addImport("input", input_mod);
    exe.root_module.addImport("output", output_mod);
    exe.root_module.addImport("mpt", mpt_mod);
    exe.root_module.addImport("deserialize", deserialize_mod);
    exe.root_module.addImport("executor", executor_mod);

    b.installArtifact(exe);

    // Test step — wire unit tests in here as they are added.
    _ = b.step("test", "Run unit tests");

    // Run step via ziskemu
    // Usage: zig build run  (requires ziskemu in PATH)
    const run_step = b.step("run", "Run the guest via Zisk emulator (ziskemu must be in PATH)");
    const run_cmd = b.addSystemCommand(&.{ "ziskemu", "-e" });
    run_cmd.addArtifactArg(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);
}
