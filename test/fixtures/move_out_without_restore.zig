// move-out-without-restore — ziglang/zig#24452 class.

const std = @import("std");

const ArrayList = struct {
    items: []u8 = &.{},
    pub fn toOwnedSlice(_: *ArrayList, _: anytype) ![]u8 {
        return &.{};
    }
};

const Allocating = struct {
    pub fn toArrayList(_: *Allocating) ArrayList {
        return .{};
    }
    pub fn setArrayList(_: *Allocating, _: ArrayList) void {}
};

// Bug — fires on `list` binding.
pub fn takeBuggy(a: *Allocating, gpa: std.mem.Allocator) ![]u8 {
    var list = a.toArrayList();
    return try list.toOwnedSlice(gpa);
}

// Control — defer restore.  Should NOT fire.
pub fn takeFixed(a: *Allocating, gpa: std.mem.Allocator) ![]u8 {
    var list = a.toArrayList();
    defer a.setArrayList(list);
    return try list.toOwnedSlice(gpa);
}
