// oven-sh/bun#29853 — type has two same-typed optional fields; destructor
// frees one but not the other.

const std = @import("std");

const QueryStringMap = struct {
    pub fn deinit(_: *QueryStringMap) void {}
};

const MatchedRoute = struct {
    // Two sibling fields with the SAME declared type.  Strong signal
    // they should be treated identically in the destructor.
    query_string_map: ?QueryStringMap = null,
    param_map: ?QueryStringMap = null,

    // BUG: deinit handles query_string_map but forgets param_map.
    // Every MatchedRoute that lazily populates param_map leaks
    // its QueryStringMap allocations.
    pub fn deinit(this: *MatchedRoute) void {
        if (this.query_string_map) |*map| {
            map.deinit();
        }
        // ← missing: if (this.param_map) |*map| map.deinit();
    }
};

// Control 1 — destructor handles both siblings.  Should NOT fire.
const Good = struct {
    a: ?QueryStringMap = null,
    b: ?QueryStringMap = null,

    pub fn deinit(this: *Good) void {
        if (this.a) |*m| m.deinit();
        if (this.b) |*m| m.deinit();
    }
};

// Control 2 — only one field of that type (no siblings).  Should
// NOT fire even if not deinit'd.
const Solo = struct {
    a: ?QueryStringMap = null,

    pub fn deinit(_: *Solo) void {}
};

// Control 3 — same-type fields but BOTH omitted from deinit (neither
// in the deinit body).  Symmetric, so we can't tell which side is
// "wrong" — skip rather than FP.
const BothMissing = struct {
    a: ?QueryStringMap = null,
    b: ?QueryStringMap = null,

    pub fn deinit(_: *BothMissing) void {}
};
