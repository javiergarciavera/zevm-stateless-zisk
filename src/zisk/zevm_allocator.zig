/// zevm_allocator shim for the Zisk zkVM build.
///
/// Replaces zevm's default src/allocator.zig (which returns std.heap.c_allocator)
/// with the Zisk bump allocator.  Injected via:
///   module.addImport("zevm_allocator", zisk_allocator_module)
/// in zevm-stateless-zisk/build.zig.
const std = @import("std");
// Import via the named 'zisk' module so that allocator.zig stays in a single
// module (the 'zisk' module), avoiding the "file exists in multiple modules" error.
const zisk = @import("zisk");

var instance = zisk.ZiskAllocator.init();

pub fn get() std.mem.Allocator {
    return instance.allocator();
}
