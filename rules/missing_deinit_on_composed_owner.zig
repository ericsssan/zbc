//! Missing-deinit-on-composed-owner detector — a struct `Outer`
//! has a `deinit` method.  One of its value-typed fields has a
//! TYPE that's a struct in the SAME FILE also exposing a cleanup
//! method (`deinit` / `close` / `destroy` / `free` / `stop` /
//! `finalize` / `dispose`).  But `Outer.deinit` doesn't call
//! `<self>.<field>.<cleanup>(...)` — the inner's destructor is
//! never invoked, so the inner's owned non-memory resources (file
//! handles, sockets, mmaps, refs) leak.
//!
//! Real-world: ziglang/zig#22683 (`StackIterator.deinit` forgot
//! `it.ma.deinit()` → `/proc/self/mem` leaked).  Same family as
//! ziglang/zig#20192 (intermediate `Dir` leaked) and
//! ziglang/zig#18651 (Thread.Pool init cleanup gap).
//!
//! Rewritten via the AST-level model_query DSL.

const std = @import("std");
const Ast = std.zig.Ast;

const fmodel = @import("../model.zig");
const mq = @import("../model_query.zig");
const query = @import("../query.zig");
const lexer = @import("../lexer.zig");
const problem = @import("../problem.zig");
const testing = @import("../testing.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const R = "missing-deinit-on-composed-owner";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(problem.Problem),
) !void {
    if (!config_mod.isEnabled(config, .missing_deinit_on_composed_owner)) return;

    const model = try cache.fileModel();

    // Find all structs that have a `deinit` method.
    const outers = try mq.findTypes(gpa, model, .{
        .kind = .struct_,
        .has_method = .{ .name_eq = "deinit" },
    });
    defer gpa.free(outers);

    for (outers) |outer| {
        const deinit = outer.findMethod("deinit").?;

        // Find this struct's value-typed fields whose declared type
        // is a struct in this file that exposes a cleanup method.
        const fields = try mq.findFields(gpa, model, tree, outer, .{
            .value_typed = true,
            .type_matches = .{ .has_method = .{ .name_pred = isCleanupName } },
        });
        defer gpa.free(fields);

        for (fields) |field| {
            // Direct: `<X>.<field>.<cleanup>(`.  X is wildcarded
            // (typically self/this).  The body pattern is built
            // per-field since `.text` needs the field's name.
            const cleanup_call = &[_]query.Atom{
                .{ .tok = .identifier },
                .{ .tok = .period },
                .{ .text = field.name },
                .{ .tok = .period },
                .{ .pred = isCleanupName },
                .paren_args,
            };
            if (mq.methodBodyContains(tree, deinit, cleanup_call)) continue;

            // Optional-unwrap: `if (X.field) |*?cap| { ... cap.<cleanup>(...); ... }`.
            // The user explicitly handled the optional and called
            // cleanup on the unwrapped capture — no leak.
            if (bodyHandlesFieldViaUnwrap(tree, deinit, field.name)) continue;

            const ti = mq.resolveFieldType(tree, model, field).?;
            try report(gpa, problems, tree, field.name_token, field.name, ti.name);
        }
    }
}

/// True iff the method's body contains an `if (X.<field>) |...cap...| { ... }`
/// shape where the if-body calls a cleanup-named method on `cap`.
/// Matches the canonical handling for `field: ?T` where T has a deinit:
///
///     pub fn deinit(self: *Outer, alloc: Allocator) void {
///         if (self.field) |*cap| cap.deinit(alloc);
///     }
///
/// Conservative: requires the if-condition's final tokens to be
/// `.<field>` (with our field name), and the capture token to be a
/// bare identifier (`|cap|` or `|*cap|`).  Doesn't try to match
/// `while (X.field) |cap|` (loops on an optional field are rare for
/// cleanup) or nested patterns.
fn bodyHandlesFieldViaUnwrap(tree: *const Ast, method: *const fmodel.MethodInfo, field_name: []const u8) bool {
    const tags = tree.tokens.items(.tag);
    const first = method.body_first;
    const last = method.body_last;
    var t: Ast.TokenIndex = first;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] != .keyword_if) continue;
        if (tags[t + 1] != .l_paren) continue;
        const rparen = lexer.matchParen(tags, t + 1, last) orelse continue;
        // The condition's last two tokens must be `.<field_name>`.
        if (rparen < t + 4) continue;
        if (tags[rparen - 2] != .period) continue;
        if (tags[rparen - 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(rparen - 1), field_name)) continue;
        // Capture: `|...|` immediately after `)`.
        if (rparen + 1 > last or tags[rparen + 1] != .pipe) continue;
        // Capture name: skip optional `*`.
        var cap_tok = rparen + 2;
        if (cap_tok <= last and tags[cap_tok] == .asterisk) cap_tok += 1;
        if (cap_tok > last or tags[cap_tok] != .identifier) continue;
        const cap_name = tree.tokenSlice(cap_tok);
        // Find the closing `|`, then the if-body extent.
        var close_pipe = cap_tok + 1;
        while (close_pipe <= last and tags[close_pipe] != .pipe) close_pipe += 1;
        if (close_pipe > last) continue;
        // Body extent: either `{ ... }` or a single statement up to `;`.
        const body_start = close_pipe + 1;
        if (body_start > last) continue;
        const body_end: Ast.TokenIndex = if (tags[body_start] == .l_brace)
            lexer.matchBrace(tags, body_start, last) orelse continue
        else
            lexer.findStmtSemicolon(tags, body_start, last) orelse continue;

        // Scan the body for `<cap_name>.<cleanup>(`.
        var k: Ast.TokenIndex = body_start;
        while (k + 3 <= body_end) : (k += 1) {
            if (tags[k] != .identifier) continue;
            if (!std.mem.eql(u8, tree.tokenSlice(k), cap_name)) continue;
            if (tags[k + 1] != .period) continue;
            if (tags[k + 2] != .identifier) continue;
            if (tags[k + 3] != .l_paren) continue;
            if (isCleanupName(tree.tokenSlice(k + 2))) return true;
        }
    }
    return false;
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
    field_tok: Ast.TokenIndex,
    field_name: []const u8,
    type_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "field `{s}: {s}` has a `deinit`-exposing type, but the outer struct's `deinit` doesn't call `<self>.{s}.deinit(...)` — the inner's owned non-memory resources (file handles, sockets, refs, mmaps) leak",
        .{ field_name, type_name, field_name },
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

test "outer deinit forgets inner field deinit fires" {
    try testing.expectFires(check, R,
        \\const MemoryAccessor = struct {
        \\    fd: i32,
        \\    pub fn deinit(self: *MemoryAccessor) void { _ = self; }
        \\};
        \\const StackIterator = struct {
        \\    ma: MemoryAccessor,
        \\    pub fn deinit(it: *StackIterator) void {
        \\        _ = it;
        \\    }
        \\};
    );
}

test "outer deinit calls inner deinit — no fire" {
    try testing.expectNoFire(check,
        \\const MemoryAccessor = struct {
        \\    pub fn deinit(self: *MemoryAccessor) void { _ = self; }
        \\};
        \\const StackIterator = struct {
        \\    ma: MemoryAccessor,
        \\    pub fn deinit(it: *StackIterator) void {
        \\        it.ma.deinit();
        \\    }
        \\};
    );
}

test "field type has no deinit — no fire" {
    try testing.expectNoFire(check,
        \\const Plain = struct { x: u32 };
        \\const Outer = struct {
        \\    p: Plain,
        \\    pub fn deinit(self: *Outer) void { _ = self; }
        \\};
    );
}

test "pointer field (likely borrow) doesn't fire" {
    try testing.expectNoFire(check,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: ?*Inner,
        \\    pub fn deinit(self: *Outer) void {
        \\        _ = self;
        \\    }
        \\};
    );
}

test "optional value-typed field (?Inner) fires" {
    try testing.expectFires(check, R,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: ?Inner,
        \\    pub fn deinit(self: *Outer) void {
        \\        _ = self;
        \\    }
        \\};
    );
}

test "optional field cleaned up via `if (x.f) |*cap| cap.deinit(...)` — no fire" {
    try testing.expectNoFire(check,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: ?Inner,
        \\    pub fn deinit(self: *Outer) void {
        \\        if (self.inner) |*cap| {
        \\            cap.deinit();
        \\        }
        \\    }
        \\};
    );
}

test "optional field unwrap with mismatched capture cleanup still recognized" {
    try testing.expectNoFire(check,
        \\const Inner = struct {
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: ?Inner,
        \\    pub fn deinit(self: *Outer) void {
        \\        if (self.inner) |inner| inner.deinit();
        \\    }
        \\};
    );
}
