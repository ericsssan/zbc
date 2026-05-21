// self-undefined-after-destroy — tigerbeetle/tigerbeetle#2687.
// The TigerStyle invariant is overwrite-THEN-free; this rule
// catches the inversion `destroy(X); X.* = undefined;` which
// writes through a freed pointer.

const std = @import("std");

const Inspector = struct {
    allocator: std.mem.Allocator,
    state: u32 = 0,

    // Bug — should fire on `inspector.* = undefined;`.
    pub fn deinitBuggy(inspector: *Inspector) void {
        inspector.allocator.destroy(inspector);
        inspector.* = undefined;
    }

    // Control 1 — correct order.  Should NOT fire.
    pub fn deinitFixed(inspector: *Inspector) void {
        const alloc = inspector.allocator;
        inspector.* = undefined;
        alloc.destroy(inspector);
    }

    // Control 2 — write into a field (also a bug).
    pub fn releaseBuggy(self: *Inspector, alloc: std.mem.Allocator) void {
        alloc.destroy(self);
        self.state = 0;
    }

    // Control 3 — destroy inside `defer` is fine: the destroy
    // fires at scope exit, AFTER the write.
    pub fn workOk(self: *Inspector, alloc: std.mem.Allocator) void {
        defer alloc.destroy(self);
        self.state = 42;
    }
};
