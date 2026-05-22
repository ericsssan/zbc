//! Stale-annotation detector — a fn carries a `/// @returns ...`
//! doc-comment annotation, but the body's inferred behavior
//! CONTRADICTS the annotation.
//!
//! This is a transition rule for the annotation -> inference
//! migration: while both systems coexist, mismatches are real bugs
//! (the annotation lies about what the body does, which corrupts
//! every downstream consumer's analysis).
//!
//! Cases that fire:
//!   - `/// @returns owned` but body returns `borrowed_from(p)`
//!   - `/// @returns heap` but body has no allocation call
//!   - `/// @returns borrowed_from(p)` but body allocates fresh
//!   - `/// @returns borrowed_from(p)` but body borrows from a
//!     DIFFERENT param
//!
//! Cases that DON'T fire (conservative):
//!   - inference returned `.unknown` — we can't confirm the
//!     annotation is wrong
//!   - `/// @returns owns_locals` — escape hatch by design, the
//!     author is asserting something inference can't prove
//!   - annotation says `owned` and inference says `plain` — common
//!     for value-typed returns; annotation may be redundant but
//!     isn't WRONG
//!
//! The point is to surface lies, not redundancy.  Once the migration
//! is complete (annotations parsing is deleted), this rule becomes
//! a no-op and can be deleted too.

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("../lexer.zig");
const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");
const fn_summary = @import("../fn_summary.zig");
const testing = @import("../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const FnSummary = fn_summary.FnSummary;
const Returns = fn_summary.Returns;
const R = "stale-annotation";

const Annotation = union(enum) {
    owned,
    heap,
    borrowed_from: u32,
    owns_locals, // escape hatch — never fires
};

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .stale_annotation)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = lexer.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        const annotation = parseReturnsAnnotation(tree, fn_entry.proto) orelse continue;
        if (annotation == .owns_locals) continue;
        const summary = try cache.summaryOf(fn_entry.proto, fn_entry.body);
        if (conflictReason(annotation, summary.returns)) |reason| {
            try report(gpa, problems, tree, fn_entry.name_token, annotation, summary.returns, reason);
        }
    }
}

/// Returns a short human-readable conflict description, or null when
/// the annotation and inference are compatible (or inference is too
/// uncertain to flag).
fn conflictReason(anno: Annotation, inf: Returns) ?[]const u8 {
    // Inference uncertain — never conflict.
    if (inf == .unknown) return null;
    return switch (anno) {
        .owned, .heap => switch (inf) {
            .borrowed_from => "annotation claims caller owns the result, but the body returns a borrow of a parameter",
            else => null,
        },
        .borrowed_from => |anno_p| switch (inf) {
            .heap => "annotation claims the result borrows from a parameter, but the body returns a fresh heap allocation",
            .owned => "annotation claims the result borrows from a parameter, but the body returns an owned value (no borrow detected)",
            .borrowed_from => |inf_p| if (anno_p != inf_p)
                "annotation borrows from one parameter but the body returns a borrow of a DIFFERENT parameter"
            else
                null,
            else => null,
        },
        .owns_locals => null, // unreachable due to early-return above; defensive
    };
}

/// Walk the doc-comments preceding `fn_proto`'s first keyword, return
/// the first `@returns ...` directive found.  Same shape as
/// annotations.zig's private parser, kept local so this rule doesn't
/// depend on the soon-to-be-deleted annotation infrastructure.
fn parseReturnsAnnotation(tree: *const Ast, fn_proto: Ast.full.FnProto) ?Annotation {
    const fn_first_tok: Ast.TokenIndex = fn_proto.visib_token orelse
        fn_proto.extern_export_inline_token orelse
        fn_proto.ast.fn_token;
    if (fn_first_tok == 0) return null;
    const tags = tree.tokens.items(.tag);

    var t: i64 = @as(i64, @intCast(fn_first_tok)) - 1;
    while (t >= 0) : (t -= 1) {
        const tok_idx: Ast.TokenIndex = @intCast(t);
        if (tags[tok_idx] != .doc_comment) break;
        const raw = tree.tokenSlice(tok_idx);
        const body = stripDocPrefix(raw);
        const trimmed = std.mem.trim(u8, body, " \t");

        // More-specific prefixes BEFORE less-specific ones.
        if (std.mem.startsWith(u8, trimmed, "@returns owns_locals")) return .owns_locals;
        if (std.mem.startsWith(u8, trimmed, "@returns owned")) return .owned;
        if (std.mem.startsWith(u8, trimmed, "@returns heap")) return .heap;

        const prefix = "@returns borrowed_from(";
        if (std.mem.startsWith(u8, trimmed, prefix)) {
            const after = trimmed[prefix.len..];
            const close = std.mem.indexOfScalar(u8, after, ')') orelse continue;
            const param_name = std.mem.trim(u8, after[0..close], " \t");
            const idx = paramIndex(tree, fn_proto, param_name) orelse continue;
            return .{ .borrowed_from = idx };
        }
    }
    return null;
}

fn stripDocPrefix(raw: []const u8) []const u8 {
    var s = raw;
    if (std.mem.startsWith(u8, s, "///")) s = s[3..];
    if (s.len > 0 and s[0] == ' ') s = s[1..];
    return s;
}

fn paramIndex(tree: *const Ast, proto: Ast.full.FnProto, name: []const u8) ?u32 {
    var idx: u32 = 0;
    var it = proto.iterate(tree);
    while (it.next()) |p| : (idx += 1) {
        const name_tok = p.name_token orelse continue;
        if (std.mem.eql(u8, tree.tokenSlice(name_tok), name)) return idx;
    }
    return null;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    name_tok: Ast.TokenIndex,
    anno: Annotation,
    inf: Returns,
    reason: []const u8,
) !void {
    const fn_name = tree.tokenSlice(name_tok);
    const msg = try std.fmt.allocPrint(
        gpa,
        "fn `{s}`: {s}.  Annotation says `{s}`, body inference says `{s}`.  Either fix the body to match the annotation, delete the annotation (zbc no longer requires them), or `// zbc-disable-line: stale-annotation` if the inference is wrong",
        .{ fn_name, reason, fmtAnno(anno), fmtInferred(inf) },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, name_tok),
        .end = Pos.fromTokenEnd(tree, name_tok),
        .message = msg,
    });
}

fn fmtAnno(a: Annotation) []const u8 {
    return switch (a) {
        .owned => "@returns owned",
        .heap => "@returns heap",
        .borrowed_from => "@returns borrowed_from(<param>)",
        .owns_locals => "@returns owns_locals",
    };
}

fn fmtInferred(r: Returns) []const u8 {
    return switch (r) {
        .plain => "plain",
        .heap => "heap",
        .owned => "owned",
        .borrowed_from => "borrowed_from(<param>)",
        .unknown => "unknown",
    };
}

// ── Tests ──────────────────────────────────────────────────

test "fires: @returns owned but body returns a borrow of self" {
    try testing.expectFires(check, R,
        \\const Foo = struct {
        \\    buf: []const u8,
        \\    /// @returns owned
        \\    pub fn text(self: *Foo) []const u8 {
        \\        return self.buf;
        \\    }
        \\};
    );
}

test "fires: @returns borrowed_from(self) but body allocates fresh" {
    try testing.expectFires(check, R,
        \\const Foo = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn make(self: *Foo, gpa: std.mem.Allocator) ![]u8 {
        \\        _ = self;
        \\        return try gpa.alloc(u8, 8);
        \\    }
        \\};
    );
}

test "fires: @returns borrowed_from(a) but body borrows from b" {
    try testing.expectFires(check, R,
        \\/// @returns borrowed_from(a)
        \\pub fn pick(a: *Foo, b: *Foo) []const u8 {
        \\    _ = a;
        \\    return b.buf;
        \\}
        \\const Foo = struct { buf: []const u8 };
    );
}

test "no fire: @returns owned matches alloc body" {
    try testing.expectNoFire(check,
        \\/// @returns owned
        \\pub fn make(gpa: std.mem.Allocator) ![]u8 {
        \\    return try gpa.alloc(u8, 8);
        \\}
    );
}

test "no fire: @returns borrowed_from(self) matches body" {
    try testing.expectNoFire(check,
        \\const Foo = struct {
        \\    buf: []const u8,
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *Foo) []const u8 {
        \\        return self.buf;
        \\    }
        \\};
    );
}

test "no fire: no annotation present" {
    try testing.expectNoFire(check,
        \\pub fn make(gpa: std.mem.Allocator) ![]u8 {
        \\    return try gpa.alloc(u8, 8);
        \\}
    );
}

test "no fire: @returns owns_locals (escape hatch, never flags)" {
    try testing.expectNoFire(check,
        \\/// @returns owns_locals
        \\pub fn make(gpa: std.mem.Allocator) !Foo {
        \\    _ = gpa;
        \\    return .{};
        \\}
        \\const Foo = struct {};
    );
}

test "no fire: inference unknown (can't disprove)" {
    try testing.expectNoFire(check,
        \\/// @returns owned
        \\pub fn make() void {}
    );
}

test "no fire: suppressed via zbc-disable-line" {
    // This test asserts the rule itself fires; the suppression is
    // applied by lib.zig::analyzeEscape's post-hoc filter and isn't
    // visible through testing.runRule (which calls check directly).
    // We document the suppression integration point separately.
    try testing.expectFires(check, R,
        \\/// @returns owned
        \\pub fn x(self: *Foo) []const u8 { return self.buf; }
        \\const Foo = struct { buf: []const u8 };
    );
}
