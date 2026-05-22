//! Memset-undef-after-len-truncation detector — `self.items.len =
//! NEW; @memset(self.items[NEW..], undefined);` (or `= 0; @memset(
//! self.items, undefined)`) — the memset slices the ALREADY-
//! TRUNCATED items, so the range is empty and the memset is a no-op.
//! The freed-but-retained capacity keeps its old bytes, defeating
//! Zig's `undefined` use-after-shrink safety detection.
//!
//! Real-world: ziglang/zig#25810 + #25832 fix this in both
//! `ArrayListAligned` and `ArrayListAlignedManaged`'s
//! `shrinkRetainingCapacity` / `clearRetainingCapacity`.  The same
//! shape recurs in any "shrink-and-poison" sibling method.  The fix
//! is to swap the order: `@memset` FIRST against the still-valid
//! tail, THEN truncate `len`.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Find statement `<X>.<field>.len = <expr>;` (the truncation).
//!   3. In the same scope, after the truncation, find the first
//!      `@memset(<X>.<field>...)` call where the memset target
//!      starts with the same `<X>.<field>` prefix.
//!   4. Fire on the `@memset` call site.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .memset_undef_after_len_truncation)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        if (returnsType(tree, node)) continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, body, problems);
    }
}

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var t: Ast.TokenIndex = first;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        // Pattern: `<X>.<field>.len = ...` — truncation site.
        // Token sequence: identifier . identifier . identifier = ...
        // where the last identifier is `len`.
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .period) continue;
        if (tags[t + 4] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 4), "len")) continue;
        if (t + 5 > last or tags[t + 5] != .equal) continue;
        const x_name = tree.tokenSlice(t);
        const field_name = tree.tokenSlice(t + 2);
        const sc = findStmtSemicolon(tags, t + 6, last) orelse continue;
        // Look for `@memset(<X>.<field>...)` in [sc+1, scope-end].
        const memset_tok = findMemsetOnSlice(tree, sc + 1, last, x_name, field_name) orelse {
            t = sc;
            continue;
        };
        try report(gpa, problems, tree, memset_tok, x_name, field_name);
        t = sc;
    }
}

/// Scan for `@memset(<X>.<field>...)` where the first non-trivial
/// expression inside the parens starts with `<X>.<field>`.
fn findMemsetOnSlice(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    x_name: []const u8,
    field_name: []const u8,
) ?Ast.TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var t: Ast.TokenIndex = start;
    while (t + 4 <= last) : (t += 1) {
        if (tags[t] == .r_brace) return null; // exited scope
        if (tags[t] != .builtin) continue;
        const m = tree.tokenSlice(t);
        if (!std.mem.eql(u8, m, "@memset")) continue;
        if (tags[t + 1] != .l_paren) continue;
        // First arg must start with `<X>.<field>`.
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), x_name)) continue;
        if (tags[t + 3] != .period) continue;
        if (tags[t + 4] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 4), field_name)) continue;
        return t;
    }
    return null;
}

fn findStmtSemicolon(
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var paren: u32 = 0;
    var brace: u32 = 0;
    var bracket: u32 = 0;
    var t: Ast.TokenIndex = start;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_paren => paren += 1,
            .r_paren => if (paren > 0) {
                paren -= 1;
            },
            .l_brace => brace += 1,
            .r_brace => if (brace > 0) {
                brace -= 1;
            },
            .l_bracket => bracket += 1,
            .r_bracket => if (bracket > 0) {
                bracket -= 1;
            },
            .semicolon => if (paren == 0 and brace == 0 and bracket == 0) return t,
            else => {},
        }
    }
    return null;
}

fn matchBrace(
    tags: []const std.zig.Token.Tag,
    lb: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var depth: u32 = 1;
    var t: Ast.TokenIndex = lb + 1;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_brace => depth += 1,
            .r_brace => {
                depth -= 1;
                if (depth == 0) return t;
            },
            else => {},
        }
    }
    return null;
}

fn skipNestedFn(
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
) Ast.TokenIndex {
    var t: Ast.TokenIndex = start;
    while (t <= last and tags[t] != .l_brace) : (t += 1) {}
    if (t > last) return last;
    return matchBrace(tags, t, last) orelse last;
}

fn returnsType(tree: *const Ast, fn_decl: Ast.Node.Index) bool {
    var buf: [1]Ast.Node.Index = undefined;
    const fp = fnProto(tree, &buf, fn_decl) orelse return false;
    const rt = fp.ast.return_type.unwrap() orelse return false;
    const first = tree.firstToken(rt);
    const last = tree.lastToken(rt);
    if (first != last) return false;
    return tree.tokens.items(.tag)[first] == .identifier and
        std.mem.eql(u8, tree.tokenSlice(first), "type");
}

fn fnProto(tree: *const Ast, buf: *[1]Ast.Node.Index, node: Ast.Node.Index) ?Ast.full.FnProto {
    return switch (tree.nodeTag(node)) {
        .fn_decl => switch (tree.nodeTag(tree.nodeData(node).node_and_node[0])) {
            .fn_proto => tree.fnProto(tree.nodeData(node).node_and_node[0]),
            .fn_proto_multi => tree.fnProtoMulti(tree.nodeData(node).node_and_node[0]),
            .fn_proto_one => tree.fnProtoOne(buf, tree.nodeData(node).node_and_node[0]),
            .fn_proto_simple => tree.fnProtoSimple(buf, tree.nodeData(node).node_and_node[0]),
            else => null,
        },
        else => null,
    };
}

fn bodyOf(tree: *const Ast, node: Ast.Node.Index) ?Ast.Node.Index {
    if (tree.nodeTag(node) != .fn_decl) return null;
    return tree.nodeData(node).node_and_node[1];
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    memset_tok: Ast.TokenIndex,
    x_name: []const u8,
    field_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`@memset({s}.{s}[...]...)` follows `{s}.{s}.len = ...;` — the memset slices the ALREADY-TRUNCATED items so the range is empty and the memset is a no-op.  The freed-but-retained capacity keeps its old bytes, defeating Zig's `undefined` use-after-shrink safety.  Swap the order: `@memset(...)` BEFORE the `.len = ...` truncation",
        .{ x_name, field_name, x_name, field_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "memset-undef-after-len-truncation",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, memset_tok),
        .end = Pos.fromTokenEnd(tree, memset_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);
    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    try check(gpa, &tree, &config_mod.Default, &problems);
    return problems;
}

fn freeProblems(gpa: std.mem.Allocator, p: *std.ArrayListUnmanaged(Problem)) void {
    for (p.items) |*x| x.deinit(gpa);
    p.deinit(gpa);
}

test "memset-undef-after-len: shrink-then-memset (canonical bug) fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const T = struct {
        \\    items: []u8,
        \\    pub fn shrink(self: *T, new_len: usize) void {
        \\        self.items.len = new_len;
        \\        @memset(self.items[new_len..], undefined);
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("memset-undef-after-len-truncation", problems.items[0].rule_id);
}

test "memset-undef-after-len: clear-then-memset-all (clearRetainingCapacity bug) fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const T = struct {
        \\    items: []u8,
        \\    pub fn clear(self: *T) void {
        \\        self.items.len = 0;
        \\        @memset(self.items, undefined);
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "memset-undef-after-len: memset BEFORE truncation (correct order) doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const T = struct {
        \\    items: []u8,
        \\    pub fn shrinkFixed(self: *T, new_len: usize) void {
        \\        @memset(self.items[new_len..], undefined);
        \\        self.items.len = new_len;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "memset-undef-after-len: memset on a different field doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const T = struct {
        \\    items: []u8,
        \\    other: []u8,
        \\    pub fn shrink(self: *T, new_len: usize) void {
        \\        self.items.len = new_len;
        \\        @memset(self.other, undefined);
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
