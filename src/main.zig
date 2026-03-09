const std      = @import("std");
const zisk     = @import("zisk");
const execute  = @import("execute.zig");
const zkvm_io  = @import("zkvm_io.zig");

/// Zisk zkVM UART address for console output
const ZISK_UART: *volatile u8 = @ptrFromInt(0xa0000200);

// Linker-provided symbols
extern const __bss_start: u8;
extern const __bss_end:   u8;

/// Write bytes to the Zisk zkVM UART
pub fn uartWrite(bytes: []const u8) void {
    for (bytes) |byte| {
        ZISK_UART.* = byte;
    }
}

/// Exit via Zisk zkVM ecall (Linux syscall 93 = exit)
fn zkExit(exit_code: u32) noreturn {
    asm volatile (
        \\ ecall
        \\ .align 4
        :
        : [exit_code] "{a0}" (exit_code),
          [syscall]   "{a7}" (93)
        : .{ .memory = true }
    );
    while (true) {
        asm volatile ("wfi");
    }
}

// ── Assembly entry point ──────────────────────────────────────────────────────
// Must be the very first thing in .text._start.  Pure asm: no Zig prologue.
comptime {
    asm (
        \\.section .text._start,"ax",%progbits
        \\.global _start
        \\.type _start, @function
        \\_start:
        \\  li sp, 0xa0120000    // Initialize stack pointer
        \\  li gp, 0xa0020000    // Initialize global pointer
        \\  call _start_main     // Jump to Zig entry
        \\  .align 4
        \\1: wfi
        \\  j 1b
        \\.size _start, . - _start
    );
}

/// First Zig function executed after sp/gp are set by _start
export fn _start_main() noreturn {
    uartWrite("INIT\n");

    main() catch |err| {
        uartWrite("ERROR: ");
        uartWrite(@errorName(err));
        uartWrite("\n");
        zkExit(1);
    };

    uartWrite("DONE\n");
    zkExit(0);
}

/// Guest entry point: read input from zkVM I/O region, run execution pipeline
pub fn main() !void {
    var zisk_alloc = zisk.ZiskAllocator.init();
    const allocator = zisk_alloc.allocator();

    const input_data = zkvm_io.read_input_slice();

    if (input_data.len == 0) {
        uartWrite("ERROR: no input data in zkVM input region\n");
        return error.NoInput;
    }

    uartWrite("Running zevm-stateless block execution...\n");
    const output = try execute.executeBlock(allocator, input_data);

    // Write ProofOutput to zkVM output region
    // Format: pre_state_root (32) | post_state_root (32) | receipts_root (32)
    zkvm_io.write_output_slice(&output.pre_state_root);
    zkvm_io.write_output_slice(&output.post_state_root);
    zkvm_io.write_output_slice(&output.receipts_root);
}

/// Panic handler for freestanding Zisk zkVM target
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    uartWrite("PANIC: ");
    uartWrite(msg);
    uartWrite("\n");
    zkExit(1);
}
