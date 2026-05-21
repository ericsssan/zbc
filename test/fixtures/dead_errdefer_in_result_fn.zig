// oven-sh/bun#27706 — `errdefer` in a fn returning `Result(T)` (tagged
// union, NOT error union) is dead code.

const std = @import("std");

fn Result(comptime T: type) type {
    return union(enum) {
        result: T,
        err: anyerror,
    };
}

const UnresolvedColor = struct {
    pub fn deinit(_: *UnresolvedColor) void {}
};

// Bug — Result(T) return + errdefer should fire.
pub fn parseColorBuggy(arg: usize) Result(UnresolvedColor) {
    _ = arg;
    var light: UnresolvedColor = .{};
    errdefer light.deinit();   // dead — never fires
    return .{ .err = error.Test };
}

// Control 1 — `!T` return.  errdefer is LIVE.  Should NOT fire.
pub fn parseColorOk(arg: usize) !UnresolvedColor {
    _ = arg;
    var light: UnresolvedColor = .{};
    errdefer light.deinit();
    return error.Test;
}

// Control 2 — Result(T) return but NO errdefer.  Should NOT fire.
pub fn parseColorClean(arg: usize) Result(UnresolvedColor) {
    _ = arg;
    return .{ .err = error.Test };
}

// Control 3 — bare value return (`Foo`, no parens).  Doesn't match
// the parameterized tagged-union shape.  Should NOT fire.
pub fn parseColorBare(arg: usize) UnresolvedColor {
    _ = arg;
    var light: UnresolvedColor = .{};
    errdefer light.deinit();
    return light;
}

// Control 4 — `?Result(T)` optional wrapper still has dead errdefer.
pub fn parseColorOptional(arg: usize) ?Result(UnresolvedColor) {
    _ = arg;
    var light: UnresolvedColor = .{};
    errdefer light.deinit();   // dead
    return null;
}
