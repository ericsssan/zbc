// oven-sh/bun#28633 / #29864 class — `this.field = X;` for a
// heap-owning field without prior `this.field.deinit()` leaks the
// old value on every reassignment.

const std = @import("std");

const Inner = struct {
    pub fn deinit(_: *Inner) void {}
};

const Owner = struct {
    inner: Inner = .{},

    // Bug — should fire (heap-owning field reassigned with no prior cleanup).
    pub fn set(this: *Owner, new_inner: Inner) void {
        this.inner = new_inner;
    }

    // Control 1 — prior `.deinit()` is OK.
    pub fn setCorrectly(this: *Owner, new_inner: Inner) void {
        this.inner.deinit();
        this.inner = new_inner;
    }

    // Control 2 — constructor name (`init`) is skipped.
    pub fn init(this: *Owner, new_inner: Inner) void {
        this.inner = new_inner;
    }

    // Control 3 — assignment inside `<X> orelse { ... }` block.
    pub fn maybeSet(this: *Owner, new_inner: Inner) void {
        const _ignored: ?*Inner = null;
        const _existing = _ignored orelse {
            this.inner = new_inner; // old guaranteed null — no leak
            return;
        };
        _ = _existing;
    }
};

// Control 4 — value-typed field (no deinit method).  Should NOT fire.
const PlainHolder = struct {
    n: u32 = 0,
    pub fn set(this: *PlainHolder, new_n: u32) void {
        this.n = new_n;
    }
};

// Control 5 — `<X> = null` sentinel write is skipped.
const Optional = struct {
    inner: ?Inner = null,
    pub fn clear(this: *Optional) void {
        this.inner = null;
    }
};
