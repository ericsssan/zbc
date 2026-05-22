//! Owned-field-no-outer-cleanup detector — a struct `Outer` has a
//! value-typed field whose type (same file) exposes a cleanup
//! method (`deinit` / `close` / `destroy` / `free` / `stop` /
//! `finalize` / `dispose`).  But `Outer` itself exposes NO cleanup
//! method.  Users who treat `Outer` as a plain value silently leak
//! the inner's owned non-memory resource (file handle, socket,
//! ref, mmap) when the outer goes out of scope.
//!
//! Complement to `missing-deinit-on-composed-owner`: that rule
//! fires when `Outer.deinit` exists but FORGETS to call
//! `<self>.<field>.deinit(...)`; this rule fires when `Outer.deinit`
//! is missing ENTIRELY.  Same family of bugs (resource leak via
//! composition), different signal in the source.
//!
//! Pointer / slice fields are excluded — the "owned pointer" vs
//! "borrowed pointer" distinction is invisible at the type level.
//! Value-typed (incl. `?T`) fields are the cleanest "I own this"
//! signal.
//!
//! Only fires ONCE per outer struct — the first qualifying field
//! is enough to indicate the design gap.

const std = @import("std");
const Ast = std.zig.Ast;

const fmodel = @import("../model.zig");
const problem = @import("../problem.zig");
const testing = @import("../testing.zig");
const trace = @import("../trace.zig");
const config_mod = @import("../config.zig");

const TokenIndex = std.zig.Ast.TokenIndex;
const R = "owned-field-no-outer-cleanup";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(problem.Problem),
) !void {
    if (!config_mod.isEnabled(config, .owned_field_no_outer_cleanup)) return;

    var model = try fmodel.build(gpa, tree);
    defer model.deinit();

    const tags = tree.tokens.items(.tag);

    for (model.types) |outer| {
        if (outer.kind != .struct_) continue;
        // Skip if outer already has any cleanup method — that's
        // covered by missing-deinit-on-composed-owner.
        if (outer.hasCleanupMethod()) {
            trace.skip(R, tree, outer.name_token, "outer has cleanup method (covered by composed-owner rule)");
            continue;
        }

        for (outer.fields) |field| {
            var ty: TokenIndex = field.type_first;
            if (tags[ty] == .question_mark) ty += 1;
            if (ty > field.type_last) continue;
            if (tags[ty] != .identifier) continue;
            const type_name = tree.tokenSlice(ty);

            const inner = model.findType(type_name) orelse continue;
            if (!inner.hasCleanupMethod()) continue;

            trace.match(R, tree, field.name_token, "owned field with no outer cleanup");
            try report(gpa, problems, tree, outer.name, field.name_token, field.name, type_name);
            break; // one fire per outer is enough
        }
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(problem.Problem),
    tree: *const Ast,
    outer_name: []const u8,
    field_tok: TokenIndex,
    field_name: []const u8,
    type_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}.{s}: {s}` owns a resource (`{s}` exposes `deinit`/`close`/etc.), but `{s}` itself has no cleanup method — dropping a `{s}` value silently leaks the inner's file handle / socket / ref / mmap.  Add `pub fn deinit(self: *{s}) void {{ self.{s}.deinit(); }}` (or equivalent)",
        .{ outer_name, field_name, type_name, type_name, outer_name, outer_name, outer_name, field_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = problem.Pos.fromTokenStart(tree, field_tok),
        .end = problem.Pos.fromTokenEnd(tree, field_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "outer has no deinit + owned field fires" {
    try testing.expectFires(check, R,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: Inner,
        \\};
    );
}

test "outer has deinit (composed-owner covers it) — no fire" {
    try testing.expectNoFire(check,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: Inner,
        \\    pub fn deinit(self: *Outer) void { _ = self; }
        \\};
    );
}

test "outer has close (alternate cleanup) — no fire" {
    try testing.expectNoFire(check,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: Inner,
        \\    pub fn close(self: *Outer) void { _ = self; }
        \\};
    );
}

test "field type has no cleanup method — no fire" {
    try testing.expectNoFire(check,
        \\const Plain = struct { x: u32 };
        \\const Outer = struct {
        \\    p: Plain,
        \\};
    );
}

test "pointer field (likely borrow) — no fire" {
    try testing.expectNoFire(check,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: *Inner,
        \\};
    );
}

test "optional value field (?Inner) fires" {
    try testing.expectFires(check, R,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: ?Inner,
        \\};
    );
}

test "multiple owned fields fires once (not per-field)" {
    try testing.expectFires(check, R,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    a: Inner,
        \\    b: Inner,
        \\    c: Inner,
        \\};
    );
}

test "Inner with finalize/dispose also counts as cleanup" {
    try testing.expectFires(check, R,
        \\const Inner = struct {
        \\    pub fn dispose(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: Inner,
        \\};
    );
}
