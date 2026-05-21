// ghostty-org/ghostty#9885 — `var sf = std.heap.stackFallback(N, alloc);`
// produces an allocator whose small allocs land in the caller's
// stack frame.  `.toOwnedSlice()` on a container built over
// `sf.get()` returns a slice into that buffer — escaping it via
// `return` dangles once the frame dies.

const std = @import("std");

const Builder = struct {
    pub fn init(_: std.mem.Allocator) Builder {
        return .{};
    }
    pub fn toOwnedSlice(_: *Builder) ![]u8 {
        return &.{};
    }
    pub fn deinit(_: *Builder) void {}
};

const Shell = struct { shell: []u8 };

// Bug — should fire.
pub fn setupBuggy(alloc: std.mem.Allocator) !Shell {
    var sf = std.heap.stackFallback(4096, alloc);
    var cmd = Builder.init(sf.get());
    defer cmd.deinit();
    return .{ .shell = try cmd.toOwnedSlice() };
}

// Control 1 — wrap in inner-alloc dupe.  Should NOT fire.
pub fn setupFixed(alloc: std.mem.Allocator) !Shell {
    var sf = std.heap.stackFallback(4096, alloc);
    var cmd = Builder.init(sf.get());
    defer cmd.deinit();
    const tmp = try cmd.toOwnedSlice();
    return .{ .shell = try alloc.dupe(u8, tmp) };
}

// Control 2 — no stackFallback present.  Should NOT fire.
pub fn setupNoSf(alloc: std.mem.Allocator) ![]u8 {
    var cmd = Builder.init(alloc);
    defer cmd.deinit();
    return try cmd.toOwnedSlice();
}

// Control 3 — tainted local consumed only locally.  Should NOT fire.
pub fn doStuff(alloc: std.mem.Allocator) !void {
    var sf = std.heap.stackFallback(4096, alloc);
    var cmd = Builder.init(sf.get());
    defer cmd.deinit();
    const slice = try cmd.toOwnedSlice();
    _ = slice;
}

// Control 4 — inline-wrapped form (the canonical fix shape that
// ghostty-org/ghostty#9885's sibling sites use).  Should NOT fire.
pub fn setupInlineFix(alloc: std.mem.Allocator) !Shell {
    var sf = std.heap.stackFallback(4096, alloc);
    var cmd = Builder.init(sf.get());
    defer cmd.deinit();
    return .{ .shell = try alloc.dupe(u8, try cmd.toOwnedSlice()) };
}
