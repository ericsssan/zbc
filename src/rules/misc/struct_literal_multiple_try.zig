//! Detects two or more `.field = try <expr>` inside the same struct literal (or
//! initializer).  If the first `try` succeeds but the second `try` propagates an
//! error, the allocation made by the first `try` leaks — `errdefer` cannot be
//! placed inside a struct literal expression.
//!
//! Real-world instance:
//!   - ziglang/zig#23285 (std.zig.Ast.parse):
//!       return Ast{
//!           .extra_data = try parser.extra_data.toOwnedSlice(gpa),  // succeeds
//!           .errors     = try parser.errors.toOwnedSlice(gpa),       // fails → leak
//!       };
//!     Fix: bind each to a local with `errdefer`, then build the struct literal
//!     from the locals.
//!
//! Detection (Tier 1, token walk with paren-skip):
//!   Pattern: `. identifier = keyword_try ... , . identifier = keyword_try`
//!   — find the first `.field = try` 4-token prefix, skip to the next `,` at
//!   depth 0, then check whether the following tokens are `. identifier = try`.
//!   Fire at the second `.` token (the start of the second field assignment).

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");
const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "struct-literal-multiple-try";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .struct_literal_multiple_try)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    if (tree.tokens.len < 8) return;
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var t: Ast.TokenIndex = 0;
    while (t + 7 <= last_tok) : (t += 1) {
        // First field: . identifier = try
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .equal) continue;
        if (tags[t + 3] != .keyword_try) continue;

        // Skip to ',' at depth 0 (end of this field's initializer)
        var i = t + 4;
        var depth: u32 = 0;
        while (i <= last_tok) : (i += 1) {
            switch (tags[i]) {
                .l_paren, .l_brace, .l_bracket => depth += 1,
                .r_paren, .r_brace, .r_bracket => {
                    if (depth == 0) break; // closing delimiter of the struct literal
                    depth -= 1;
                },
                .comma => if (depth == 0) break,
                else => {},
            }
        }
        if (i > last_tok) continue;
        if (tags[i] != .comma) continue; // hit a closing delimiter — skip

        // Check the next field starts with . identifier = try
        const next = i + 1;
        if (next + 3 > last_tok) continue;
        if (tags[next] != .period) continue;
        if (tags[next + 1] != .identifier) continue;
        if (tags[next + 2] != .equal) continue;
        if (tags[next + 3] != .keyword_try) continue;

        const field1 = tree.tokenSlice(t + 1);
        const field2 = tree.tokenSlice(next + 1);

        try report(gpa, problems, tree, next, field1, field2);
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    second_tok: Ast.TokenIndex,
    field1: []const u8,
    field2: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`.{s} = try ...` followed by `.{s} = try ...` in the same initializer — if the second `try` fails, the allocation from the first leaks because `errdefer` cannot appear inside a struct literal; bind each to a local with `errdefer` first",
        .{ field1, field2 },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, second_tok),
        .end = Pos.fromTokenEnd(tree, second_tok + 3),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "struct-literal-multiple-try: fires on two try fields" {
    try testing.expectFires(check, R,
        \\fn parse(gpa: Allocator, parser: *Parser) !Ast {
        \\    return Ast{
        \\        .extra_data = try parser.extra_data.toOwnedSlice(gpa),
        \\        .errors     = try parser.errors.toOwnedSlice(gpa),
        \\    };
        \\}
        \\
    );
}

test "struct-literal-multiple-try: single try field does not fire" {
    try testing.expectNoFire(check,
        \\fn parse(gpa: Allocator, parser: *Parser) !Ast {
        \\    return Ast{
        \\        .extra_data = try parser.extra_data.toOwnedSlice(gpa),
        \\        .errors     = &.{},
        \\    };
        \\}
        \\
    );
}

test "struct-literal-multiple-try: non-try second field does not fire" {
    try testing.expectNoFire(check,
        \\fn build() Foo {
        \\    return Foo{
        \\        .a = compute(),
        \\        .b = 42,
        \\    };
        \\}
        \\
    );
}

test "struct-literal-multiple-try: fires in return with named init" {
    try testing.expectFires(check, R,
        \\fn makeNode(gpa: Allocator) !Node {
        \\    return Node{
        \\        .name  = try gpa.dupe(u8, "hello"),
        \\        .value = try gpa.dupe(u8, "world"),
        \\    };
        \\}
        \\
    );
}

test "struct-literal-multiple-try: try in nested call args does not fire" {
    try testing.expectNoFire(check,
        \\fn callFn(a: u8, b: u8) void {
        \\    process(a, b);
        \\}
        \\
    );
}
