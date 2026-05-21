// PR #29854 — `this.<X> = heap;` then `this.* = StructLit{…}` that
// omits `.<X>` — heap pointer silently dropped to default.

const std = @import("std");

const PathWatcher = struct {
    path: []const u8 = "",
    callback: usize = 0,
    resolved_path: ?[:0]const u8 = null,

    pub fn deinit(this: *PathWatcher) void {
        if (this.resolved_path) |p| {
            std.heap.page_allocator.free(@constCast(p));
        }
    }
};

// Bug — should fire.
pub fn initBuggy(this: *PathWatcher, path: []const u8) !void {
    const resolved_path = try std.heap.page_allocator.dupeZ(u8, path);
    this.resolved_path = resolved_path;
    this.* = PathWatcher{
        .path = path,
        .callback = 0,
        // .resolved_path omitted — clobbered to null on reset
    };
}

// Control 1 — literal carries the field forward.  Should NOT fire.
pub fn initFixed(this: *PathWatcher, path: []const u8) !void {
    const resolved_path = try std.heap.page_allocator.dupeZ(u8, path);
    this.resolved_path = resolved_path;
    this.* = PathWatcher{
        .path = path,
        .callback = 0,
        .resolved_path = resolved_path,
    };
}

// Control 2 — prior RHS is a sentinel default (`null`).  Should NOT
// fire (the reset just preserves the default).
pub fn initSentinel(this: *PathWatcher, path: []const u8) void {
    this.resolved_path = null;
    this.* = PathWatcher{
        .path = path,
        .callback = 0,
    };
}

// Control 3 — no struct-literal reset, just field assignments.  Should
// NOT fire.
pub fn initFieldOnly(this: *PathWatcher, path: []const u8) !void {
    this.resolved_path = try std.heap.page_allocator.dupeZ(u8, path);
    this.path = path;
}
