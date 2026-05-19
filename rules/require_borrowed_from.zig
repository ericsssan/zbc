//! `ez/require-borrowed-from` — Layer 1 annotation hygiene rule.
//!
//! Flags public functions that return a borrowed-shape type (`[]const u8`,
//! `[]const T`, `*const T`, `*T`) from a borrowed-source parameter
//! (`*const Ast`, `*Ast`, `*const LintContext`, etc.) WITHOUT a
//! `/// @returns borrowed_from(<param>)` doc comment.
//!
//! Layer 2's escape analyzer needs that annotation to track the return
//! value's lifetime origin. Missing annotation = silently disabled
//! checking for that path.
//!
//! Also flags annotations that name a parameter that doesn't exist or
//! isn't a borrowed-source type (typo prevention).

const std = @import("std");
const Ast = std.zig.Ast;
const problem_mod = @import("../problem.zig");
const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

const RULE_ID = "ez/require-borrowed-from";

pub const Config = struct {
    severity: problem_mod.Severity = .@"error",
    /// Type names whose pointer/slice forms count as "borrowed-source".
    /// Functions taking these as `*const T` / `*T` are subject to the rule.
    borrowed_source_types: []const []const u8 = &.{
        "Ast",
        "LintContext",
        "Source",
        "ArenaAllocator",
        "Parser",
    },
};

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cfg: Config,
    out: *std.ArrayListUnmanaged(Problem),
) !void {
    if (cfg.severity == .off) return;

    // Walk every node looking for fn protos (decl or expression form).
    var node_idx: u32 = 1; // skip root
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        var buf: [1]Ast.Node.Index = undefined;
        const fn_proto = fullFnProto(tree, &buf, node) orelse continue;
        try checkFn(gpa, tree, cfg, fn_proto, out);
    }
}

/// Returns the FnProto view if `node` is one of the four fn-proto tags
/// AND has a name token (anonymous fn expressions are excluded).
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
    // 1) Must be public — look for `pub` keyword at visib_token.
    if (fn_proto.visib_token == null) return;
    if (tree.tokens.items(.tag)[fn_proto.visib_token.?] != .keyword_pub) return;

    // 2) Return type must be borrowed-shape.
    const ret_type_node = fn_proto.ast.return_type.unwrap() orelse return;
    if (!returnTypeIsBorrowed(tree, ret_type_node)) return;

    // 3) Collect borrowed-source params.
    var borrowed_params: std.ArrayListUnmanaged([]const u8) = .empty;
    defer borrowed_params.deinit(gpa);
    try collectBorrowedParams(tree, fn_proto, cfg.borrowed_source_types, gpa, &borrowed_params);
    if (borrowed_params.items.len == 0) return;

    // 4) Parse `@returns` annotation from preceding doc comments.
    const annotation = parseReturnsAnnotation(tree, fn_proto);

    const name_tok = fn_proto.name_token.?;

    switch (annotation) {
        .borrowed_from => |param_name| {
            var found = false;
            for (borrowed_params.items) |p| {
                if (std.mem.eql(u8, p, param_name)) { found = true; break; }
            }
            if (!found) {
                try report(gpa, tree, name_tok, cfg.severity, out,
                    "@returns borrowed_from({s}) names a parameter that doesn't exist or isn't a borrowed-source type",
                    .{param_name});
            }
        },
        .owned => {}, // explicit opt-out — caller owns the return value despite borrowed-shape type
        .missing => {
            try report(gpa, tree, name_tok, cfg.severity, out,
                "fn returns a borrowed-shape type from a borrowed-source parameter; add `/// @returns borrowed_from(<param>)`",
                .{});
        },
    }
}

/// True for `[]const T`, `[]T`, `*const T`, `*T`, `[*]T`, `[*]const T`.
/// Recurses through optional `?T` and error-union `!T` payloads.
///
/// Implemented over source text rather than Node.Data variants — the Data
/// union shape churns between Zig versions and the source text is stable.
/// Looks for a leading `[`, `[*`, or `*` after stripping `?` / `!T!`.
fn returnTypeIsBorrowed(tree: *const Ast, node: Ast.Node.Index) bool {
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    const start = tree.tokens.items(.start)[first];
    const last_start = tree.tokens.items(.start)[last];
    const last_len = tree.tokenSlice(last).len;
    const end: usize = last_start + last_len;
    var text = tree.source[start..end];
    // Strip leading `?`, `!`, and whitespace from error/optional unions.
    while (text.len > 0) {
        switch (text[0]) {
            '?' => { text = text[1..]; continue; },
            '!' => { text = text[1..]; continue; },
            ' ', '\t' => { text = text[1..]; continue; },
            else => break,
        }
        // Also handle `E!T` where E is an explicit error set name.
        // Find a `!` and recurse on the rhs.
    }
    // Handle `E!T` — split on the first `!` that isn't inside parens.
    if (std.mem.indexOfScalar(u8, text, '!')) |bang_pos| {
        // Re-evaluate the RHS as a fresh type text.
        text = std.mem.trimStart(u8, text[bang_pos + 1 ..], " \t");
    }
    // `*T`, `*const T`, `[*]T`, `[*c]T`, `[]T`, `[]const T` all start with
    // `*` or `[`. Value types start with an identifier or builtin.
    return text.len > 0 and (text[0] == '*' or text[0] == '[');
}

fn collectBorrowedParams(
    tree: *const Ast,
    fn_proto: Ast.full.FnProto,
    source_types: []const []const u8,
    gpa: std.mem.Allocator,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    var it = fn_proto.iterate(tree);
    while (it.next()) |param| {
        const param_name_tok = param.name_token orelse continue;
        const param_type_node = param.type_expr orelse continue;

        // Param must be a pointer to one of the source types.
        const tag = tree.nodeTag(param_type_node);
        const is_ptr = switch (tag) {
            .ptr_type, .ptr_type_aligned, .ptr_type_bit_range, .ptr_type_sentinel => true,
            else => false,
        };
        if (!is_ptr) continue;

        // Pointee — main_token of the pointer node is `*` / `[*]` etc.;
        // the pointee identifier is the main token of the ptr_type's child node.
        // Simplest: scan tokens between the pointer node's start and the param's
        // end for an `.identifier` token that matches one of source_types.
        if (pointeeMatchesAny(tree, param_type_node, source_types)) {
            try out.append(gpa, tree.tokenSlice(param_name_tok));
        }
    }
}

/// True if the pointer-type subtree references an identifier from `names`.
/// Conservative — walks the subtree's tokens looking for matching idents.
fn pointeeMatchesAny(tree: *const Ast, node: Ast.Node.Index, names: []const []const u8) bool {
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        if (tree.tokens.items(.tag)[t] != .identifier) continue;
        const text = tree.tokenSlice(t);
        for (names) |n| {
            if (std.mem.eql(u8, text, n)) return true;
        }
    }
    return false;
}

const Annotation = union(enum) {
    missing,
    owned,
    borrowed_from: []const u8, // slice into the source buffer
};

/// Scan doc comments preceding the fn for `@returns borrowed_from(NAME)`
/// or `@returns owned`. Doc comments in Zig are `.doc_comment` tokens
/// stacked immediately before the decl.
fn parseReturnsAnnotation(tree: *const Ast, fn_proto: Ast.full.FnProto) Annotation {
    // First token of the fn proto = either visib_token (pub), extern_export,
    // or fn_token. Walk back from there over .doc_comment tokens.
    const fn_first_tok: Ast.TokenIndex = fn_proto.visib_token orelse
        fn_proto.extern_export_inline_token orelse
        fn_proto.ast.fn_token;
    if (fn_first_tok == 0) return .missing;

    var t: i64 = @as(i64, @intCast(fn_first_tok)) - 1;
    while (t >= 0) : (t -= 1) {
        const tok_idx: Ast.TokenIndex = @intCast(t);
        const tag = tree.tokens.items(.tag)[tok_idx];
        if (tag != .doc_comment) break;
        // Get the comment text (after `/// `).
        const raw = tree.tokenSlice(tok_idx);
        const body = stripDocPrefix(raw);
        if (matchOwned(body)) return .owned;
        if (matchBorrowedFrom(body)) |name| return .{ .borrowed_from = name };
    }
    return .missing;
}

fn stripDocPrefix(raw: []const u8) []const u8 {
    // raw starts with "///"; may have a space.
    var s = raw;
    if (std.mem.startsWith(u8, s, "///")) s = s[3..];
    if (s.len > 0 and s[0] == ' ') s = s[1..];
    return s;
}

fn matchOwned(body: []const u8) bool {
    // Looking for "@returns owned" (possibly with trailing whitespace/punctuation).
    const prefix = "@returns owned";
    const trimmed = std.mem.trim(u8, body, " \t");
    return std.mem.startsWith(u8, trimmed, prefix);
}

fn matchBorrowedFrom(body: []const u8) ?[]const u8 {
    const prefix = "@returns borrowed_from(";
    const trimmed = std.mem.trim(u8, body, " \t");
    if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
    const after = trimmed[prefix.len..];
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

test "missing annotation on borrowed-returning fn" {
    const gpa = std.testing.allocator;
    const src =
        \\const Ast = struct {};
        \\pub fn tokenText(self: *const Ast, tok: u32) []const u8 {
        \\    _ = self; _ = tok;
        \\    return "";
        \\}
        \\
    ;
    try expectProblems(gpa, src, &.{
        .{ .line = 2, .substring = "add `/// @returns borrowed_from" },
    });
}

test "correct annotation passes" {
    const gpa = std.testing.allocator;
    const src =
        \\const Ast = struct {};
        \\/// @returns borrowed_from(self)
        \\pub fn tokenText(self: *const Ast, tok: u32) []const u8 {
        \\    _ = self; _ = tok;
        \\    return "";
        \\}
        \\
    ;
    try expectProblems(gpa, src, &.{});
}

test "annotation pointing at nonexistent param flagged" {
    const gpa = std.testing.allocator;
    const src =
        \\const Ast = struct {};
        \\/// @returns borrowed_from(typo_param)
        \\pub fn tokenText(self: *const Ast, tok: u32) []const u8 {
        \\    _ = self; _ = tok;
        \\    return "";
        \\}
        \\
    ;
    try expectProblems(gpa, src, &.{
        .{ .line = 3, .substring = "names a parameter that doesn't exist" },
    });
}

test "owned annotation on borrowed-shape return accepted (opt-out)" {
    const gpa = std.testing.allocator;
    const src =
        \\const Ast = struct {};
        \\/// @returns owned
        \\pub fn dupedText(self: *const Ast, gpa: u32) ![]const u8 {
        \\    _ = self; _ = gpa;
        \\    return "";
        \\}
        \\
    ;
    try expectProblems(gpa, src, &.{});
}

test "non-public fn skipped" {
    const gpa = std.testing.allocator;
    const src =
        \\const Ast = struct {};
        \\fn tokenText(self: *const Ast, tok: u32) []const u8 {
        \\    _ = self; _ = tok;
        \\    return "";
        \\}
        \\
    ;
    try expectProblems(gpa, src, &.{});
}

test "value-typed return skipped" {
    const gpa = std.testing.allocator;
    const src =
        \\const Ast = struct {};
        \\pub fn nodeSpan(self: *const Ast, n: u32) u64 {
        \\    _ = self; _ = n;
        \\    return 0;
        \\}
        \\
    ;
    try expectProblems(gpa, src, &.{});
}

test "no borrowed-source param skipped" {
    const gpa = std.testing.allocator;
    const src =
        \\pub fn someFn(x: u32) []const u8 {
        \\    _ = x;
        \\    return "";
        \\}
        \\
    ;
    try expectProblems(gpa, src, &.{});
}

const Expected = struct {
    line: u32,
    substring: []const u8,
};

fn expectProblems(gpa: std.mem.Allocator, src: []const u8, expected: []const Expected) !void {
    const src_z = try gpa.dupeZ(u8, src);
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
        for (problems.items) |p| {
            std.debug.print("  line {}: {s}\n", .{ p.start.line, p.message });
        }
        return error.WrongProblemCount;
    }
    for (problems.items, expected) |p, e| {
        try std.testing.expectEqual(e.line, p.start.line);
        if (std.mem.indexOf(u8, p.message, e.substring) == null) {
            std.debug.print("\nexpected message containing '{s}', got '{s}'\n", .{ e.substring, p.message });
            return error.MessageMismatch;
        }
    }
}
