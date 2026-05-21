// PR #29452 — `<x>.realloc(slice, n * @sizeOf(T))` over-allocates.

const std = @import("std");

const Selector = struct { name: []const u8 };

// Bug — should fire.
fn tryGrowBuggy(allocator: std.mem.Allocator, ptr: [*]Selector, length: usize, cap: usize, new_cap: usize) []Selector {
    _ = cap;
    return allocator.realloc(ptr[0..length], new_cap * @sizeOf(Selector)) catch unreachable;
}

// Control 1 — correct: element count, no @sizeOf multiplier.
fn tryGrowFixed(allocator: std.mem.Allocator, ptr: [*]Selector, cap: usize, new_cap: usize) []Selector {
    return allocator.realloc(ptr[0..cap], new_cap) catch unreachable;
}

// Control 2 — @sizeOf used elsewhere (slice indexing), NOT in arg2.
fn tryGrowComplex(allocator: std.mem.Allocator, ptr: [*]Selector, cap: usize, new_cap: usize) []Selector {
    const offset = @sizeOf(Selector); // declaration of sizeof — different position
    _ = offset;
    return allocator.realloc(ptr[0..cap], new_cap) catch unreachable;
}

// Control 3 — @sizeOf in arg2, but bound to a local first.  Should NOT fire.
fn tryGrowExplicitBytes(allocator: std.mem.Allocator, ptr: [*]u8, cap: usize, new_cap: usize) []u8 {
    const new_bytes = new_cap * @sizeOf(Selector);
    return allocator.realloc(ptr[0..cap], new_bytes) catch unreachable;
}
