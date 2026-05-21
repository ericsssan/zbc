// HashMap getPtr-rehash class — `const p = map.getPtr(k).?;` followed
// by a receiver-matched mutating call on `map` (`put`, `remove`,
// `fetchPut`, ...) followed by a use of `p` → UAF against table
// storage if the mutation rehashed.

const std = @import("std");

// Bug — should fire on `p.* = 99;`.
pub fn buggy(map: *std.AutoHashMap(u32, u32)) !void {
    const p = map.getPtr(1) orelse return;
    try map.put(2, 20);
    p.* = 99;
}

// Bug — getOrPut variant; field access through the GetOrPutResult
// is the dangling pointer.  Should fire on `gop`'s subsequent use.
pub fn buggyGop(map: *std.AutoHashMap(u32, u32)) !void {
    const gop = try map.getOrPut(1);
    try map.put(2, 20);
    gop.value_ptr.* = 99;
}

// Control 1 — use happens BEFORE the mutating call.  Should NOT fire.
pub fn okBeforePut(map: *std.AutoHashMap(u32, u32)) !void {
    const p = map.getPtr(1) orelse return;
    p.* = 99;
    try map.put(2, 20);
}

// Control 2 — different receiver mutated.  Should NOT fire.
pub fn okDifferentMap(
    a: *std.AutoHashMap(u32, u32),
    b: *std.AutoHashMap(u32, u32),
) !void {
    const p = a.getPtr(1) orelse return;
    try b.put(2, 20);
    p.* = 99;
}

// Control 3 — non-mutating `.get` between borrow and use.  Should NOT
// fire.  `.get` returns a value, not a pointer, and doesn't touch
// capacity.
pub fn okGetBetween(map: *std.AutoHashMap(u32, u32)) !void {
    const p = map.getPtr(1) orelse return;
    _ = map.get(2);
    p.* = 99;
}
