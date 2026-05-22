//! oven-sh/bun#29968 detector — `<x>.free(X);` immediately followed by
//! `X = try …;` with no intervening reset of `X` to a sentinel.
//! If the `try` propagates an error, `X` is left pointing at
//! freed memory; a subsequent `deinit` then re-frees it.
//!
//! Pure two-adjacent-statements token scan per fn body.

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("../lexer.zig");
const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");
const testing = @import("../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

const bodyOf = lexer.bodyOf;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .free_then_try_realloc)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
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
    while (t + 4 < last) : (t += 1) {
        // Locate `<…>.free(<X>);` at statement position.
        // Pattern: `period identifier(free) l_paren <X> r_paren semicolon`.
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 1), "free")) continue;
        if (tags[t + 2] != .l_paren) continue;
        // Find matching `)` at depth 1 of the `(`.
        const open = t + 2;
        var depth: u32 = 1;
        var u: Ast.TokenIndex = open + 1;
        while (u <= last) : (u += 1) {
            switch (tags[u]) {
                .l_paren => depth += 1,
                .r_paren => {
                    depth -= 1;
                    if (depth == 0) break;
                },
                else => {},
            }
        }
        if (depth != 0) continue;
        const close = u;
        if (close + 1 > last) continue;
        if (tags[close + 1] != .semicolon) continue;
        const sc = close + 1;

        // Capture the free's argument tokens (between open and close,
        // exclusive of both).  These are the X we expect on the
        // next statement's LHS.
        const arg_first: Ast.TokenIndex = open + 1;
        const arg_last: Ast.TokenIndex = close - 1;
        if (arg_first > arg_last) {
            t = sc;
            continue;
        }

        // Check the next stmt's start.  Skip closing braces (`}`)
        // — the free is often inside an `if` / `while` block while
        // the realloc-try lives in the enclosing scope.  Skipping
        // `}` (without going further past intervening statements)
        // pairs the two correctly.  We DON'T skip past other tokens
        // because real code between the free and the realloc may
        // change `X` in ways we can't reason about.
        var stmt_start: Ast.TokenIndex = sc + 1;
        while (stmt_start <= last and tags[stmt_start] == .r_brace) : (stmt_start += 1) {}
        const lhs_first: Ast.TokenIndex = stmt_start;
        const lhs_count = (arg_last - arg_first) + 1;
        if (lhs_first + lhs_count + 1 > last) {
            t = sc;
            continue;
        }
        var ok = true;
        var i: usize = 0;
        while (i < lhs_count) : (i += 1) {
            const a = arg_first + @as(Ast.TokenIndex, @intCast(i));
            const b = lhs_first + @as(Ast.TokenIndex, @intCast(i));
            if (tags[a] != tags[b]) {
                ok = false;
                break;
            }
            if (!std.mem.eql(u8, tree.tokenSlice(a), tree.tokenSlice(b))) {
                ok = false;
                break;
            }
        }
        if (!ok) {
            t = sc;
            continue;
        }
        const eq_tok = lhs_first + @as(Ast.TokenIndex, @intCast(lhs_count));
        if (eq_tok > last or tags[eq_tok] != .equal) {
            t = sc;
            continue;
        }
        if (eq_tok + 1 > last or tags[eq_tok + 1] != .keyword_try) {
            t = sc;
            continue;
        }

        // Match — fire at the `.free(` call's period.
        try report(gpa, problems, tree, t, arg_first, arg_last);
        t = sc;
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    period_tok: Ast.TokenIndex,
    arg_first: Ast.TokenIndex,
    arg_last: Ast.TokenIndex,
) !void {
    const starts = tree.tokens.items(.start);
    const arg_start = starts[arg_first];
    const arg_end = starts[arg_last] + tree.tokenSlice(arg_last).len;
    const arg_text = tree.source[arg_start..arg_end];

    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}` is freed here and then immediately reassigned through `try`; if the `try`'s alloc fails, `{s}` is left dangling and a later `deinit` re-frees it.  Insert `{s} = &.{{}};` (or `null`/`undefined` per the field's type) between the free and the realloc",
        .{ arg_text, arg_text, arg_text },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "free-then-try-realloc",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, period_tok + 1),
        .end = Pos.fromTokenEnd(tree, period_tok + 1),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    return testing.runRule(gpa, check, src);
}

const freeProblems = testing.freeProblems;

test "free-then-try-realloc: adjacent free + try-alloc fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const T = struct { x: u32 };
        \\const S = struct { columns: []T = &.{} };
        \\pub fn refill(s: *S, n: usize) !void {
        \\    std.heap.page_allocator.free(s.columns);
        \\    s.columns = try std.heap.page_allocator.alloc(T, n);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("free-then-try-realloc", problems.items[0].rule_id);
}

test "free-then-try-realloc: clearing between free and try is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const T = struct { x: u32 };
        \\const S = struct { columns: []T = &.{} };
        \\pub fn refill(s: *S, n: usize) !void {
        \\    std.heap.page_allocator.free(s.columns);
        \\    s.columns = &.{};
        \\    s.columns = try std.heap.page_allocator.alloc(T, n);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "free-then-try-realloc: `catch unreachable` instead of `try` is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const T = struct { x: u32 };
        \\const S = struct { columns: []T = &.{} };
        \\pub fn refill(s: *S, n: usize) void {
        \\    std.heap.page_allocator.free(s.columns);
        \\    s.columns = std.heap.page_allocator.alloc(T, n) catch unreachable;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "free-then-try-realloc: free in inner `if`, try in outer scope still fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const T = struct { x: u32 };
        \\const S = struct { columns: []T = &.{} };
        \\pub fn refill(s: *S, n: usize, cond: bool) !void {
        \\    if (cond) {
        \\        std.heap.page_allocator.free(s.columns);
        \\    }
        \\    s.columns = try std.heap.page_allocator.alloc(T, n);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "free-then-try-realloc: free followed by unrelated stmt then try doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const T = struct { x: u32 };
        \\const S = struct { columns: []T = &.{} };
        \\pub fn refill(s: *S, n: usize) !void {
        \\    std.heap.page_allocator.free(s.columns);
        \\    const x: u32 = 0;
        \\    _ = x;
        \\    s.columns = try std.heap.page_allocator.alloc(T, n);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
