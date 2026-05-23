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
        // Bun convention skip: `pub const new = bun.TrivialNew(T);`
        // (or `bun.New(T)`) declares the type as heap-allocated and
        // owned by a parent — the parent's deinit handles the
        // teardown, so absence of a deinit on T isn't a leak.  This
        // is a strong signal in Bun's codebase and orthogonal to
        // the "plain value type" case the rule targets.
        if (hasNewFactoryDecl(tree, outer)) continue;
        // Same convention via init-shape: `init(...) !*@This()` /
        // `init(...) *Self` means the struct is heap-allocated and
        // owned by an external caller — cleanup happens at the
        // owner's hand, not via a fn on the value.
        if (hasPointerReturningInit(tree, outer)) continue;
        // Find the first value-typed field whose type has a NON-TRIVIAL
        // cleanup method.  If the inner type's `deinit` (or whichever
        // cleanup method) has an empty / discard-only body, it does
        // nothing on drop — skipping the outer is harmless.  Common
        // for CSS/value-type uniform-API conformance: `pub fn deinit
        // (_: *@This(), _: Allocator) void {}`.
        const fields = try mq.findFields(gpa, model, tree, outer, .{
            .value_typed = true,
            .type_matches = .{ .has_method = .{ .name_pred = isCleanupName } },
        });
        defer gpa.free(fields);

        var hit: ?usize = null;
        for (fields, 0..) |f, i| {
            const inner_ti = mq.resolveFieldType(tree, model, f) orelse continue;
            if (anyNonTrivialCleanup(tree, inner_ti)) {
                hit = i;
                break;
            }
        }
        const idx = hit orelse continue;
        const field = fields[idx];
        const inner = mq.resolveFieldType(tree, model, field).?;
        trace.match(R, tree, field.name_token, "owned field with no outer cleanup");
        try report(gpa, problems, tree, outer.name, field.name_token, field.name, inner.name);
    }
}

/// True iff the type has an `init` / `create` / `new` method whose
/// return type is `*Self` (after stripping `!` and `?`).  Pointer-
/// returning constructors mark the type as heap-allocated and
/// owned by an external caller — common in Bun's JSC bridge
/// (`globalThis.allocator().create(@This())`).  The outer's
/// missing inline cleanup isn't a leak because the owning caller
/// is responsible for teardown.
fn hasPointerReturningInit(tree: *const Ast, ti: *const fmodel.TypeInfo) bool {
    const tags = tree.tokens.items(.tag);
    for (ti.methods) |m| {
        if (!std.mem.eql(u8, m.name, "init") and
            !std.mem.eql(u8, m.name, "create") and
            !std.mem.eql(u8, m.name, "new")) continue;
        var buf: [1]Ast.Node.Index = undefined;
        const proto = tree.fullFnProto(&buf, m.fn_decl) orelse continue;
        const rt = proto.ast.return_type.unwrap() orelse continue;
        const first = tree.firstToken(rt);
        if (tags[first] == .asterisk) return true;
        // `?*T`: `?` then `*` next.
        if (tags[first] == .question_mark and first + 1 < tree.tokens.len and tags[first + 1] == .asterisk) return true;
    }
    return false;
}

/// True iff the type body declares a `pub const new = ...` (or
/// `const new = ...`) initializer that names a heap-factory call —
/// `bun.TrivialNew(T)` / `bun.New(T)`.  Bun convention: such types
/// are heap-allocated and owned by a parent struct that's
/// responsible for cleanup, so a missing inline `deinit` on `T`
/// isn't a leak.  Token-scan over the type body for the prefix.
fn hasNewFactoryDecl(tree: *const Ast, ti: *const fmodel.TypeInfo) bool {
    const tags = tree.tokens.items(.tag);
    if (ti.body_first >= ti.body_last) return false;
    var t: Ast.TokenIndex = ti.body_first;
    while (t + 4 < ti.body_last) : (t += 1) {
        // Match `[pub] const new =`.
        var k: Ast.TokenIndex = t;
        if (tags[k] == .keyword_pub) k += 1;
        if (tags[k] != .keyword_const) continue;
        if (tags[k + 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(k + 1), "new")) continue;
        if (tags[k + 2] != .equal) continue;
        // RHS must be a call expression — common factory shapes:
        // `bun.TrivialNew(T)`, `bun.New(T)`.  Look at next few
        // tokens for an identifier (or `bun.<id>`) followed by `(`.
        var r: Ast.TokenIndex = k + 3;
        while (r < ti.body_last and (tags[r] == .identifier or tags[r] == .period)) : (r += 1) {}
        if (r < ti.body_last and tags[r] == .l_paren) return true;
    }
    return false;
}

/// True iff `ti` has at least one cleanup-named method whose body is
/// non-trivial — i.e. contains something other than `_ = <expr>;`
/// discards.  An empty `{}` or all-discards body means the method
/// does nothing on drop, so a missing outer cleanup is harmless.
fn anyNonTrivialCleanup(tree: *const Ast, ti: *const fmodel.TypeInfo) bool {
    for (ti.methods) |m| {
        if (!isCleanupName(m.name)) continue;
        if (!isTrivialBody(tree, m.body_first, m.body_last)) return true;
    }
    return false;
}

/// True iff the body `[body_first..body_last]` (inclusive `{` ... `}`)
/// is empty or contains only `_ = <expr>;` discard statements.
fn isTrivialBody(tree: *const Ast, body_first: Ast.TokenIndex, body_last: Ast.TokenIndex) bool {
    const tags = tree.tokens.items(.tag);
    if (body_first >= body_last) return true;
    // body_first is `{`, body_last is `}`.  Empty body: nothing between.
    if (body_first + 1 == body_last) return true;
    // Walk statements; require each to be a discard.
    var t: Ast.TokenIndex = body_first + 1;
    while (t < body_last) {
        // Allowed start: `_` identifier followed by `=`.
        if (tags[t] != .identifier) return false;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "_")) return false;
        if (t + 1 >= body_last or tags[t + 1] != .equal) return false;
        // Skip to the statement-terminating `;` at depth 0.
        var depth: u32 = 0;
        var k = t + 2;
        while (k < body_last) : (k += 1) {
            switch (tags[k]) {
                .l_paren, .l_brace, .l_bracket => depth += 1,
                .r_paren, .r_brace, .r_bracket => {
                    if (depth == 0) return false;
                    depth -= 1;
                },
                .semicolon => if (depth == 0) break,
                else => {},
            }
        }
        if (k >= body_last or tags[k] != .semicolon) return false;
        t = k + 1;
    }
    return true;
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
        \\    fd: i32 = 0,
        \\    pub fn deinit(self: *Inner) void { self.fd = -1; }
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
        \\    fd: i32 = 0,
        \\    pub fn deinit(self: *Inner) void { self.fd = -1; }
        \\};
        \\const Outer = struct {
        \\    inner: ?Inner,
        \\};
    );
}

test "multiple owned fields fires once (not per-field)" {
    try testing.expectFires(check, R,
        \\const Inner = struct {
        \\    fd: i32 = 0,
        \\    pub fn deinit(self: *Inner) void { self.fd = -1; }
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
        \\    fd: i32 = 0,
        \\    pub fn dispose(self: *Inner) void { self.fd = -1; }
        \\};
        \\const Outer = struct {
        \\    inner: Inner,
        \\};
    );
}

test "Inner with empty deinit body (no-op trait conformance) — no fire" {
    // Common for CSS/value-type uniform-API conformance: deinit
    // exists for trait-method-call uniformity but does nothing.
    // Missing outer deinit doesn't leak anything.
    try testing.expectNoFire(check,
        \\const Inner = struct {
        \\    pub fn deinit(_: *Inner, _: Allocator) void {}
        \\};
        \\const Allocator = struct {};
        \\const Outer = struct {
        \\    inner: Inner,
        \\};
    );
}

test "Inner with discard-only deinit body — no fire" {
    // `pub fn deinit(self: *T) void { _ = self; }` — placeholder
    // pattern.  Same as empty body: does nothing on drop.
    try testing.expectNoFire(check,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: Inner,
        \\};
    );
}
