// PR #30169 — heap-owning local bound via `try Type.method(...)`
// without an errdefer registered before the next `try`.

const std = @import("std");

const PathLike = struct {
    bytes: []u8,

    pub fn fromJS(_: usize, _: usize) !?PathLike {
        return PathLike{ .bytes = try std.heap.page_allocator.alloc(u8, 16) };
    }

    pub fn deinit(self: *PathLike) void {
        std.heap.page_allocator.free(self.bytes);
    }
};

// Bug — should fire on `old_path`.
pub fn renameBuggy(ctx: usize, arg1: usize, arg2: usize) !struct { old: PathLike, new: PathLike } {
    const old_path = try PathLike.fromJS(ctx, arg1) orelse return error.Invalid;
    // ← missing: errdefer old_path.deinit();
    const new_path = try PathLike.fromJS(ctx, arg2) orelse return error.Invalid;
    return .{ .old = old_path, .new = new_path };
}

// Control 1 — errdefer registered immediately.  Should NOT fire.
pub fn renameFixed(ctx: usize, arg1: usize, arg2: usize) !struct { old: PathLike, new: PathLike } {
    var old_path = try PathLike.fromJS(ctx, arg1) orelse return error.Invalid;
    errdefer old_path.deinit();
    var new_path = try PathLike.fromJS(ctx, arg2) orelse return error.Invalid;
    errdefer new_path.deinit();
    return .{ .old = old_path, .new = new_path };
}

// Control 2 — single `try` in scope, no second try to leak through.
pub fn renameSingle(ctx: usize, arg1: usize) !PathLike {
    const old_path = try PathLike.fromJS(ctx, arg1) orelse return error.Invalid;
    return old_path;
}

// Control 3 — binding's type has no deinit method (the local isn't
// heap-owned).  Should NOT fire even with multiple `try`s.
const PlainValue = struct {
    n: u32,
    pub fn fromJS(_: usize) !PlainValue {
        return .{ .n = 42 };
    }
};

pub fn plainTries(ctx: usize) !u32 {
    const a = try PlainValue.fromJS(ctx);
    const b = try PlainValue.fromJS(ctx);
    return a.n + b.n;
}
