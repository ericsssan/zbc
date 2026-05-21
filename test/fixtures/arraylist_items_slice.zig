// ArrayList items-slice rehash class — `const items = list.items;`
// followed by a receiver-matched mutating call (`.append`,
// `.appendSlice`, `.insert`, ...) followed by a use of `items` →
// UAF against list storage if the mutation reallocated.

const std = @import("std");

// Bug — should fire on `items[0] = 99;`.
pub fn buggy(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
    const items = list.items;
    try list.append(gpa, 1);
    items[0] = 99;
}

// Bug — `appendSlice` variant.
pub fn buggySlice(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
    const items = list.items;
    try list.appendSlice(gpa, &.{ 1, 2, 3 });
    items[0] = 99;
}

// Bug — `insert` shifts and may reallocate.
pub fn buggyInsert(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
    const items = list.items;
    try list.insert(gpa, 0, 99);
    items[1] = 99;
}

// Control 1 — use before append.  Should NOT fire.
pub fn okBefore(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
    const items = list.items;
    items[0] = 99;
    try list.append(gpa, 1);
}

// Control 2 — different list mutated.  Should NOT fire.
pub fn okDifferent(
    a: *std.ArrayList(u32),
    b: *std.ArrayList(u32),
    gpa: std.mem.Allocator,
) !void {
    const items = a.items;
    try b.append(gpa, 1);
    items[0] = 99;
}

// Control 3 — `appendAssumeCapacity` doesn't realloc by contract.
// Should NOT fire.
pub fn okAssumeCapacity(list: *std.ArrayList(u32)) void {
    const items = list.items;
    list.appendAssumeCapacity(99);
    items[0] = 99;
}

// Control 4 — pre-allocation idiom: `ensureUnusedCapacity` BEFORE
// the borrow.  Should NOT fire (and after `appendAssumeCapacity`
// the borrow is still valid).
pub fn okPreAlloc(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
    try list.ensureUnusedCapacity(gpa, 1);
    const items = list.items;
    list.appendAssumeCapacity(99);
    items[0] = 99;
}
