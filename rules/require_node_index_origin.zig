//! `ez/require-node-index-origin` — Layer 1 annotation hygiene rule.
//!
//! Flags public functions that take a `NodeIndex` parameter WITHOUT a
//! `/// @takes node_index_of(<param>)` or `/// @takes node_index_any`
//! doc comment.
//!
//! Layer 2's escape analyzer uses this annotation to verify that a
//! NodeIndex flowing in came from the right Ast. Without it, the
//! analyzer treats the parameter as "unknown origin" — which silently
//! disables identity checking for that path.
//!
//! Most fns in our codebase take `self: *const LintContext` + a
//! NodeIndex; the LintContext holds the Ast, so `node_index_of(self)`
//! is the standard annotation. Direct `*const Ast` takes use
//! `node_index_of(ast)`.

const std = @import("std");
const Ast = std.zig.Ast;
const problem_mod = @import("../problem.zig");
const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

const RULE_ID = "ez/require-node-index-origin";

pub const Config = struct {
    severity: problem_mod.Severity = .@"error",
    /// Type names that "carry" an Ast and so are valid `node_index_of(X)`
    /// targets. Functions whose only borrowed-source param is one of
    /// these should annotate `node_index_of(<that_param>)`.
    ///
    /// "Pass-context" types (CodePathBuilder, Semantic, etc.) count too:
    /// they hold per-pass state derived from an Ast and any NodeIndex
    /// they receive is implicitly scoped to that Ast.
    ast_holder_types: []const []const u8 = &.{
        // Direct Ast holders
        "Ast",
        "LintContext",
        "Parser",
        // Pass-context holders
        "CodePathBuilder",
        "Semantic",
        "EventResolver",
        "Linter",
    },
};

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cfg: Config,
    out: *std.ArrayListUnmanaged(Problem),
) !void {
    if (cfg.severity == .off) return;
    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        var buf: [1]Ast.Node.Index = undefined;
        const fn_proto = fullFnProto(tree, &buf, node) orelse continue;
        try checkFn(gpa, tree, cfg, fn_proto, out);
    }
}

fn fullFnProto(tree: *const Ast, buf: *[1]Ast.Node.Index, node: Ast.Node.Index) ?Ast.full.FnProto {
    const proto: ?Ast.full.FnProto = switch (tree.nodeTag(node)) {
        .fn_proto => tree.fnProto(node),
        .fn_proto_multi => tree.fnProtoMulti(node),
        .fn_proto_one => tree.fnProtoOne(buf, node),
        .fn_proto_simple => tree.fnProtoSimple(buf, node),
        else => null,
    };
    const p = proto orelse return null;
    if (p.name_token == null) return null;
    return p;
}

fn checkFn(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cfg: Config,
    fn_proto: Ast.full.FnProto,
    out: *std.ArrayListUnmanaged(Problem),
) !void {
    if (fn_proto.visib_token == null) return;
    if (tree.tokens.items(.tag)[fn_proto.visib_token.?] != .keyword_pub) return;

    // Walk params, collect:
    //   - ast-holder param names (for valid @takes targets)
    //   - whether any NodeIndex param is present
    var ast_holders: std.ArrayListUnmanaged([]const u8) = .empty;
    defer ast_holders.deinit(gpa);
    var has_node_index = false;

    var it = fn_proto.iterate(tree);
    while (it.next()) |param| {
        const name_tok = param.name_token orelse continue;
        const type_node = param.type_expr orelse continue;
        const param_name = tree.tokenSlice(name_tok);

        if (paramTypeIs(tree, type_node, "NodeIndex")) {
            // Methods on NodeIndex itself (`pub fn unwrap(self: NodeIndex)
            // ...`) aren't consumers — they're pure conversions/accessors
            // on the type.  Don't subject them to the origin check.
            if (std.mem.eql(u8, param_name, "self")) continue;
            has_node_index = true;
            continue;
        }
        if (paramIsPointerTo(tree, type_node, cfg.ast_holder_types)) {
            try ast_holders.append(gpa, param_name);
        }
    }

    if (!has_node_index) return;

    const annotation = parseTakesAnnotation(tree, fn_proto);
    const name_tok = fn_proto.name_token.?;

    switch (annotation) {
        .node_index_of => |target| {
            var found = false;
            for (ast_holders.items) |h| {
                if (std.mem.eql(u8, h, target)) { found = true; break; }
            }
            if (!found) {
                try report(gpa, tree, name_tok, cfg.severity, out,
                    "@takes node_index_of({s}) names a parameter that doesn't exist or isn't an Ast-holder type",
                    .{target});
            }
        },
        .node_index_any => {}, // explicit opt-out — fine
        .missing => {
            // Inference fast-path: exactly one Ast-holder param ⇒ the
            // NodeIndex's origin is unambiguous, no annotation needed.
            // Annotation is required only when:
            //   - zero ast holders (free-floating NodeIndex — explicit
            //     node_index_any expected)
            //   - two or more (ambiguity — must say which one)
            if (ast_holders.items.len == 1) return;
            try report(gpa, tree, name_tok, cfg.severity, out,
                "fn takes a NodeIndex with {} Ast-holder params — origin is ambiguous; add `/// @takes node_index_of(<param>)` or `/// @takes node_index_any`",
                .{ast_holders.items.len});
        },
    }
}

fn paramTypeIs(tree: *const Ast, type_node: Ast.Node.Index, name: []const u8) bool {
    // Direct identifier match for simple unqualified type names.
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    if (first != last) return false;
    if (tree.tokens.items(.tag)[first] != .identifier) return false;
    return std.mem.eql(u8, tree.tokenSlice(first), name);
}

fn paramIsPointerTo(tree: *const Ast, type_node: Ast.Node.Index, names: []const []const u8) bool {
    const tag = tree.nodeTag(type_node);
    const is_ptr = switch (tag) {
        .ptr_type, .ptr_type_aligned, .ptr_type_bit_range, .ptr_type_sentinel => true,
        else => false,
    };
    if (!is_ptr) return false;
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        if (tree.tokens.items(.tag)[t] != .identifier) continue;
        const text = tree.tokenSlice(t);
        for (names) |n| if (std.mem.eql(u8, text, n)) return true;
    }
    return false;
}

const Annotation = union(enum) {
    missing,
    node_index_any,
    node_index_of: []const u8,
};

fn parseTakesAnnotation(tree: *const Ast, fn_proto: Ast.full.FnProto) Annotation {
    const fn_first_tok: Ast.TokenIndex = fn_proto.visib_token orelse
        fn_proto.extern_export_inline_token orelse
        fn_proto.ast.fn_token;
    if (fn_first_tok == 0) return .missing;

    var t: i64 = @as(i64, @intCast(fn_first_tok)) - 1;
    while (t >= 0) : (t -= 1) {
        const tok_idx: Ast.TokenIndex = @intCast(t);
        if (tree.tokens.items(.tag)[tok_idx] != .doc_comment) break;
        const raw = tree.tokenSlice(tok_idx);
        const body = stripDocPrefix(raw);
        if (matchAny(body)) return .node_index_any;
        if (matchOf(body)) |name| return .{ .node_index_of = name };
    }
    return .missing;
}

fn stripDocPrefix(raw: []const u8) []const u8 {
    var s = raw;
    if (std.mem.startsWith(u8, s, "///")) s = s[3..];
    if (s.len > 0 and s[0] == ' ') s = s[1..];
    return s;
}

fn matchAny(body: []const u8) bool {
    const t = std.mem.trim(u8, body, " \t");
    return std.mem.startsWith(u8, t, "@takes node_index_any");
}

fn matchOf(body: []const u8) ?[]const u8 {
    const t = std.mem.trim(u8, body, " \t");
    const prefix = "@takes node_index_of(";
    if (!std.mem.startsWith(u8, t, prefix)) return null;
    const after = t[prefix.len..];
    const close = std.mem.indexOfScalar(u8, after, ')') orelse return null;
    return std.mem.trim(u8, after[0..close], " \t");
}

fn report(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    tok: Ast.TokenIndex,
    severity: problem_mod.Severity,
    out: *std.ArrayListUnmanaged(Problem),
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const msg = try std.fmt.allocPrint(gpa, fmt, args);
    try out.append(gpa, .{
        .rule_id = RULE_ID,
        .severity = severity,
        .start = Pos.fromTokenStart(tree, tok),
        .end = Pos.fromTokenEnd(tree, tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

const Expected = struct {
    line: u32,
    substring: []const u8,
};

fn expectProblems(gpa: std.mem.Allocator, src: []const u8, expected: []const Expected) !void {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(src_z);

    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);

    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    defer {
        for (problems.items) |*p| p.deinit(gpa);
        problems.deinit(gpa);
    }

    try check(gpa, &tree, .{}, &problems);

    if (problems.items.len != expected.len) {
        std.debug.print("\nexpected {} problems, got {}:\n", .{ expected.len, problems.items.len });
        for (problems.items) |p| std.debug.print("  line {}: {s}\n", .{ p.start.line, p.message });
        return error.WrongProblemCount;
    }
    for (problems.items, expected) |p, e| {
        try std.testing.expectEqual(e.line, p.start.line);
        if (std.mem.indexOf(u8, p.message, e.substring) == null) {
            std.debug.print("expected '{s}', got '{s}'\n", .{ e.substring, p.message });
            return error.MessageMismatch;
        }
    }
}

test "single Ast-holder param inferred — no annotation needed" {
    const src =
        \\const LintContext = struct {};
        \\const NodeIndex = u32;
        \\pub fn nodeTag(self: *const LintContext, n: NodeIndex) u8 {
        \\    _ = self; _ = n; return 0;
        \\}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "two Ast-holder params requires annotation (ambiguous origin)" {
    const src =
        \\const Ast = struct {};
        \\const LintContext = struct {};
        \\const NodeIndex = u32;
        \\pub fn crossAst(ctx: *const LintContext, ast: *const Ast, n: NodeIndex) u8 {
        \\    _ = ctx; _ = ast; _ = n; return 0;
        \\}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{
        .{ .line = 4, .substring = "with 2 Ast-holder params" },
    });
}

test "zero Ast-holder params requires annotation" {
    const src =
        \\const NodeIndex = u32;
        \\pub fn freeFloating(n: NodeIndex) bool {
        \\    _ = n; return false;
        \\}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{
        .{ .line = 2, .substring = "with 0 Ast-holder params" },
    });
}

test "correct node_index_of annotation passes" {
    const src =
        \\const LintContext = struct {};
        \\const NodeIndex = u32;
        \\/// @takes node_index_of(self)
        \\pub fn nodeTag(self: *const LintContext, n: NodeIndex) u8 {
        \\    _ = self; _ = n; return 0;
        \\}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "node_index_any passes" {
    const src =
        \\const NodeIndex = u32;
        \\/// @takes node_index_any
        \\pub fn freeFloating(n: NodeIndex) bool {
        \\    _ = n; return false;
        \\}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "typo in node_index_of flagged" {
    const src =
        \\const LintContext = struct {};
        \\const NodeIndex = u32;
        \\/// @takes node_index_of(typo)
        \\pub fn nodeTag(self: *const LintContext, n: NodeIndex) u8 {
        \\    _ = self; _ = n; return 0;
        \\}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{
        .{ .line = 4, .substring = "names a parameter that doesn't exist" },
    });
}

test "no NodeIndex param skipped" {
    const src =
        \\const LintContext = struct {};
        \\pub fn isEmpty(self: *const LintContext) bool {
        \\    _ = self; return false;
        \\}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "non-public skipped" {
    const src =
        \\const LintContext = struct {};
        \\const NodeIndex = u32;
        \\fn nodeTag(self: *const LintContext, n: NodeIndex) u8 {
        \\    _ = self; _ = n; return 0;
        \\}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}
