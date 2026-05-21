// `<alloc>.destroy(<recv>.<field>)` / `.free(<recv>.<field>)` in a
// non-destructor fn, without `<recv>.<field> = null;` reset → slot
// dangles; later `if (<recv>.<field>) |h| use(h)` passes the optional
// null-check and UAFs.  oven-sh/bun#30148 / #30176 / #29983 / #29988
// class.

const std = @import("std");

const Handlers = struct {
    mode: u8 = 0,
};

const Self = struct {
    gpa: std.mem.Allocator,
    handlers: ?*Handlers = null,
    specifier: []const u8 = "",

    // Bug — fires on `.destroy(`.
    pub fn markInactive(self: *Self) void {
        self.gpa.destroy(self.handlers.?);
    }

    // Bug — `free` variant.
    pub fn cancel(self: *Self) void {
        self.gpa.free(self.specifier);
    }

    // Control 1 — reset to null.  Should NOT fire.
    pub fn markInactiveOk(self: *Self) void {
        self.gpa.destroy(self.handlers.?);
        self.handlers = null;
    }

    // Control 2 — reset to empty slice.  Should NOT fire.
    pub fn cancelOk(self: *Self) void {
        self.gpa.free(self.specifier);
        self.specifier = &.{};
    }

    // Control 3 — destructor (deinit) is skipped.  Should NOT fire.
    pub fn deinit(self: *Self) void {
        self.gpa.destroy(self.handlers.?);
        self.gpa.free(self.specifier);
    }
};
