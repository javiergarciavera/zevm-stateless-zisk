/// zkVM I/O Interface for Zisk
///
/// Implements Option 2 (Direct Buffer Interface) from the zkvm-standards spec.
/// Input and output are memory-mapped regions in the Zisk address space.
const std = @import("std");

/// Zisk zkVM memory regions
const ZISK_INPUT_BASE: usize = 0x90000000;
const ZISK_INPUT_SIZE: usize = 0x08000000; // 128MB
const ZISK_OUTPUT_BASE: usize = 0xa0010000;
const ZISK_OUTPUT_SIZE: usize = 0x00010000; // 64KB

/// Track output position for sequential writes
var output_pos: usize = 0;

/// Read the private input data.
///
/// Input region layout:
///   [0..8]   free_input (u64, value = 0)
///   [8..16]  input_len  (u64, little-endian)
///   [16..]   data bytes (input_len bytes)
///
/// Returns pointer + size.  Size == 0 means no input.
pub fn read_input(buf_ptr: *[*]const u8, buf_size: *usize) void {
    const size_ptr: *const u64 = @ptrFromInt(ZISK_INPUT_BASE + 8);
    const input_size = std.mem.littleToNative(u64, size_ptr.*);

    if (input_size == 0 or input_size > ZISK_INPUT_SIZE - 16) {
        buf_ptr.* = @ptrFromInt(ZISK_INPUT_BASE);
        buf_size.* = 0;
        return;
    }

    buf_ptr.* = @ptrFromInt(ZISK_INPUT_BASE + 16);
    buf_size.* = input_size;
}

/// Write public output data.  Multiple calls concatenate sequentially.
pub fn write_output(output: [*]const u8, size: usize) void {
    if (output_pos + size > ZISK_OUTPUT_SIZE) {
        @panic("Output exceeds OUTPUT region size (64KB)");
    }
    const output_region: [*]u8 = @ptrFromInt(ZISK_OUTPUT_BASE);
    @memcpy((output_region + output_pos)[0..size], output[0..size]);
    output_pos += size;
}

/// Helper: read input as a slice
pub fn read_input_slice() []const u8 {
    var buf_ptr: [*]const u8 = undefined;
    var buf_size: usize = 0;
    read_input(&buf_ptr, &buf_size);
    return buf_ptr[0..buf_size];
}

/// Helper: write output from a slice
pub fn write_output_slice(output: []const u8) void {
    write_output(output.ptr, output.len);
}
