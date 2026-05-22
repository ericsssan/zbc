//! Owned-field-no-outer-cleanup detector — a struct `Outer` has a
//! value-typed field whose type (same file) exposes a cleanup
//! method (`deinit` / `close` / `destroy` / `free` / `stop` /
//! `finalize` / `dispose`).  But `Outer` itself exposes NO cleanup
//! method.  Users who treat `Outer` as a plain value silently leak
//! the inner's owned non-memory resource (file handle, socket,
//! ref, mmap) when the outer goes out of scope.
//!
//! Complement to `missing-deinit-on-composed-owner`: that rule
//! fires when `Outer.deinit` EXISTS but FORGETS to call
//! `<self>.<field>.deinit(...)`; this rule fires when `Outer.deinit`
//! is missing ENTIRELY.
//!
//! Rewritten via the AST-level model_query DSL.

const std = @import("std");
const Ast = std.zig.Ast;

const fmodel = @import("../model.zig");
const mq = @import("../model_query.zig");
const problem = @import("../problem.zig");
const testing = @import("../testing.zig");
const trace = @import("../trace.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const R = "owned-field-no-outer-cleanup";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(problem.Problem),
) !void {
    if (!config_mod.isEnabled(config, .owned_field_no_outer_cleanup)) return;

    const model = try cache.fileModel();

    // Find all structs that lack ANY cleanup method.  The
    // missing-deinit-on-composed-owner rule covers the case where
    // a cleanup method DOES exist but forgets the field.
    const outers = try mq.findTypes(gpa, model, .{
        .kind = .struct_,
        .no_method = .{ .name_pred = isCleanupName },
    });
    defer gpa.free(outers);

    for (outers) |outer| {
        // Find the first value-typed field whose type has a cleanup
        // method.  Only one fire per outer (the design gap is the
        // missing method, not the field count).
        const fields = try mq.findFields(gpa, model, tree, outer, .{
            .value_typed = true,
            .type_matches = .{ .has_method = .{ .name_pred = isCleanupName } },
        });
        defer gpa.free(fields);

        if (fields.len == 0) continue;
        const field = fields[0];
        const inner = mq.resolveFieldType(tree, model, field).?;
        trace.match(R, tree, field.name_token, "owned field with no outer cleanup");
        try report(gpa, problems, tree, outer.name, field.name_token, field.name, inner.name);
    }
}

fn isCleanupName(name: []const u8) bool {
    return std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "close") or
        std.mem.eql(u8, name, "destroy") or
        std.mem.eql(u8, name, "free") or
        std.mem.eql(u8, name, "stop") or
        std.mem.eql(u8, name, "finalize") or
        std.mem.eql(u8, name, "dispose");
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(problem.Problem),
    tree: *const Ast,
    outer_name: []const u8,
    field_tok: Ast.TokenIndex,
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
