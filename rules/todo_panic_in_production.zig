//! `@panic("TODO ...")` / `@panic("unimplemented")` /
//! `@panic("FIXME ...")` / `@panic("WIP ...")` left in code
//! that may run in release builds.  TODO-panics are a
//! development scaffold: harmless during prototyping but
//! escalate to runtime crashes if the path is reached in
//! production.
//!
//! Real-world: bun and other large Zig codebases periodically
//! ship TODO-panics that crash users when the placeholder
//! branch is hit.  CI catches some via tests; many slip
//! through.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Walk for `@panic(` builtin calls.
//!   2. Inspect the first argument's string literal.
//!   3. Match prefix patterns:
//!        TODO / FIXME / XXX / HACK / WIP
//!        "unimplemented" / "not implemented"
//!        "not yet" / "stub"
//!   4. Fire on the `@panic` call site.
//!
//! Distinct from `unreachable`: that's the canonical Zig
//! "this branch can't be reached" marker.  Most `unreachable`
//! sites are intentional (after exhaustive switch arms, after
//! proven-non-null unwraps).  Distinguishing
//! intentional-vs-TODO `unreachable` would need flow
//! analysis, so this rule targets only the `@panic(<msg>)`
//! form where the author wrote a clear human signal.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const lexer = @import("../lexer.zig");
const testing = @import("../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

const skipNestedFn = lexer.skipNestedFn;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .todo_panic_in_production)) return;
    _ = cache;
    try lexer.forEachFnBody(gpa, tree, problems, checkBody);
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
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .builtin) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "@panic")) continue;
        if (tags[t + 1] != .l_paren) continue;
        if (tags[t + 2] != .string_literal) continue;
        // Strip surrounding quotes.
        const lit = tree.tokenSlice(t + 2);
        if (lit.len < 2) continue;
        const inner = lit[1 .. lit.len - 1];
        if (!isTodoMessage(inner)) continue;
        try report(gpa, problems, tree, t, inner);
    }
}

/// True iff the panic message looks like a TODO marker.
/// Case-insensitive prefix matching for common signals.
fn isTodoMessage(msg: []const u8) bool {
    if (startsWithIgnoreCase(msg, "todo")) return true;
    if (startsWithIgnoreCase(msg, "fixme")) return true;
    if (startsWithIgnoreCase(msg, "xxx")) return true;
    if (startsWithIgnoreCase(msg, "hack")) return true;
    if (startsWithIgnoreCase(msg, "wip")) return true;
    if (startsWithIgnoreCase(msg, "unimplemented")) return true;
    if (startsWithIgnoreCase(msg, "not implemented")) return true;
    if (startsWithIgnoreCase(msg, "not yet")) return true;
    if (startsWithIgnoreCase(msg, "stub")) return true;
    if (containsIgnoreCase(msg, "TODO")) return true;
    return false;
}

fn startsWithIgnoreCase(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    for (prefix, 0..) |pc, i| {
        if (asciiToLower(s[i]) != asciiToLower(pc)) return false;
    }
    return true;
}

fn containsIgnoreCase(s: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > s.len) return false;
    var i: usize = 0;
    while (i + needle.len <= s.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            if (asciiToLower(s[i + j]) != asciiToLower(nc)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

fn asciiToLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + ('a' - 'A');
    return c;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    panic_tok: Ast.TokenIndex,
    msg_text: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`@panic(\"{s}\")` is a TODO/unimplemented marker — if this branch is reached in a release build it crashes the user's process.  Either return an explicit error (`return error.NotYetImplemented;` if the fn is in an error-union return shape) or ensure the branch is unreachable by construction (gate at compile time with `comptime` checks / static dispatch)",
        .{msg_text},
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = "todo-panic-in-production",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, panic_tok),
        .end = Pos.fromTokenEnd(tree, panic_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    return testing.runRule(gpa, check, src);
}

const freeProblems = testing.freeProblems;

test "todo-panic-in-production: @panic(\"TODO\") fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo() void {
        \\    @panic("TODO: implement this");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("todo-panic-in-production", problems.items[0].rule_id);
}

test "todo-panic-in-production: @panic(\"unimplemented\") fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo() void {
        \\    @panic("unimplemented");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "todo-panic-in-production: @panic(\"FIXME ...\") fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo() void {
        \\    @panic("FIXME: handle the edge case");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "todo-panic-in-production: regular @panic does NOT fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo() void {
        \\    @panic("internal assertion failure");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "todo-panic-in-production: unreachable does NOT fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo(x: u8) u8 {
        \\    return switch (x) {
        \\        0 => 1,
        \\        1 => 2,
        \\        else => unreachable,
        \\    };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "todo-panic-in-production: case-insensitive TODO inside message fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo() void {
        \\    @panic("internal: todo handle this");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}
