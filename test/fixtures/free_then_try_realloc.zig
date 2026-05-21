// oven-sh/bun#29968 — `<x>.free(X); X = try alloc(...);` leaves X dangling
// on alloc failure.

const std = @import("std");

const Column = struct { name: []const u8 };

const Statement = struct {
    columns: []Column = &.{},

    pub fn deinit(this: *Statement, allocator: std.mem.Allocator) void {
        for (this.columns) |col| _ = col;
        allocator.free(this.columns);
    }
};

// Bug — should fire.
pub fn refillBuggy(statement: *Statement, count: usize) !void {
    std.heap.page_allocator.free(statement.columns);
    statement.columns = try std.heap.page_allocator.alloc(Column, count);
}

// Control 1 — clears the slice between free and realloc.  Should
// NOT fire.
pub fn refillFixed(statement: *Statement, count: usize) !void {
    std.heap.page_allocator.free(statement.columns);
    statement.columns = &.{};
    statement.columns = try std.heap.page_allocator.alloc(Column, count);
}

// Control 2 — realloc without `try` (infallible / catch-handled).
// Should NOT fire.
pub fn refillCatch(statement: *Statement, count: usize) void {
    std.heap.page_allocator.free(statement.columns);
    statement.columns = std.heap.page_allocator.alloc(Column, count) catch unreachable;
}

// Control 3 — free, then unrelated stmt, then realloc.  Should NOT
// fire (the two are not adjacent).
pub fn refillSpaced(statement: *Statement, count: usize, log: anytype) !void {
    std.heap.page_allocator.free(statement.columns);
    try log.write("reallocating");
    statement.columns = try std.heap.page_allocator.alloc(Column, count);
}
