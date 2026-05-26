// oven-sh/bun#28633 / #29864 class — `this.field = X;` for a
// heap-owning field without prior `this.field.deinit()` leaks the
// old value on every reassignment.

const std = @import("std");

// Trivial deinit (empty body) — overwriting this field can't leak anything,
// so the rule does NOT fire.  A non-trivial deinit is required for the rule
// to consider a field heap-owning.
const Inner = struct {
    pub fn deinit(_: *Inner) void {}
};

// A type whose deinit does real cleanup — reassigning without prior cleanup
// fires overwrite-without-deinit when the field has no `.{}` default.
const InnerReal = struct {
    buf: []const u8 = &.{},
    pub fn deinit(self: *InnerReal) void { self.buf = &.{}; }
};

const Owner = struct {
    inner: Inner = .{},
    // Field default is `.{}` — the rule conservatively suppresses the FIRST
    // write in any method (that value holds no resources yet).  Subsequent
    // writes within the same function DO fire.
    inner_real: InnerReal = .{},

    pub fn deinit(this: *Owner) void { this.inner_real.deinit(); }

    // Control — trivial deinit means nothing to leak, does NOT fire.
    pub fn setTrivial(this: *Owner, new_inner: Inner) void {
        this.inner = new_inner;
    }

    // Control — first write to a `.{}`-defaulted field is suppressed; the
    // initial `.{}` holds no resources so there is nothing to deinit yet.
    pub fn set(this: *Owner, new_inner: InnerReal) void {
        this.inner_real = new_inner;
    }

    // Bug — second write in the same call fires because `priorWriteInFn`
    // detects that the field was already set earlier in this invocation.
    pub fn resetTwice(this: *Owner, a: InnerReal, b: InnerReal) void {
        this.inner_real = a;      // suppressed (first write, default .{})
        this.inner_real = b;      // fires — prior value `a` has no cleanup
    }

    // Control 1 — prior `.deinit()` is OK.
    pub fn setRealCorrectly(this: *Owner, new_inner: InnerReal) void {
        this.inner_real.deinit();
        this.inner_real = new_inner;
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

// Bug — field has no default, so the empty-struct-literal suppression does
// not apply.  Overwriting `inner_real` without prior cleanup fires.
const OwnerNoDefault = struct {
    inner_real: InnerReal,
    pub fn deinit(this: *OwnerNoDefault) void { this.inner_real.deinit(); }
    pub fn set(this: *OwnerNoDefault, new_inner: InnerReal) void {
        this.inner_real = new_inner; // fires
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
