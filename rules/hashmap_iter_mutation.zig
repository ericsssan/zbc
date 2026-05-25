//! HashMap iterator-invalidation-via-mutation detector.
//!
//! `var iter = <map>.<iter-method>();`
//! `while (iter.next()) |...| { ... <map>.<mutate>(...) ... }`
//!
//! Modifying a HashMap while iterating it (via `iterator()`,
//! `keyIterator()`, or `valueIterator()`) invalidates the iterator's
//! internal cursor.  Subsequent calls to `iter.next()` have undefined
//! behaviour — on Zig's open-addressing hash table the cursor may
//! revisit the same slot, skip slots, or run off the end.
//!
//! Complementary to [[iterator-invalidation-mutation]] which detects
//! the `for (list.items)` / ArrayList variant.
//!
//! Detection (per-fn token walk):
//!   1. Find `const/var <iter> = <recv>.<iter-method>()` bindings
//!      where iter-method ∈ {iterator, keyIterator, valueIterator}.
//!      Limit to single-identifier receivers to avoid FPs on chained
//!      or namespaced expressions.
//!   2. After the binding `;`, scan for `while (<iter>.next()) [|…|]`
//!      loop headers.
//!   3. Scan the while loop body for `<recv>.<mutate>(` calls at the
//!      SAME lexical block depth (nested blocks are skipped since they
//!      don't always execute).
//!   4. Fire at the mutation call site with a note pointing back to
//!      the `while` header.
//!
//! Mutate-method allowlist:
//!   put / putAssumeCapacity / putNoClobber / putNoClobberAssumeCapacity
//!   remove / removeByPtr / fetchPut / fetchRemove / swapRemove /
//!   clearAndFree / clearRetainingCapacity.
//!
//! Suppression: mutations inside `defer`/`errdefer` are skipped
//! (deferred, not inline), consistent with other rules.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const lexer = @import("../lexer.zig");
const testing = @import("../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const matchBrace = lexer.matchBrace;
const matchParen = lexer.matchParen;
const skipNestedFn = lexer.skipNestedFn;
const skipDeferStmt = lexer.skipDeferStmt;
const findStmtSemicolon = lexer.findStmtSemicolon;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .hashmap_iter_mutation)) return;
    _ = cache;
    try lexer.forEachFnBody(gpa, tree, problems, checkBody);
}

fn isIteratorMethod(s: []const u8) bool {
    return std.mem.eql(u8, s, "iterator") or
        std.mem.eql(u8, s, "keyIterator") or
        std.mem.eql(u8, s, "valueIterator");
}

fn isMutateMethod(s: []const u8) bool {
    return std.mem.eql(u8, s, "put") or
        std.mem.eql(u8, s, "putAssumeCapacity") or
        std.mem.eql(u8, s, "putNoClobber") or
        std.mem.eql(u8, s, "putNoClobberAssumeCapacity") or
        std.mem.eql(u8, s, "remove") or
        std.mem.eql(u8, s, "removeByPtr") or
        std.mem.eql(u8, s, "fetchPut") or
        std.mem.eql(u8, s, "fetchRemove") or
        std.mem.eql(u8, s, "swapRemove") or
        std.mem.eql(u8, s, "clearAndFree") or
        std.mem.eql(u8, s, "clearRetainingCapacity");
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

        // Match `<recv> . <iter-method> ( )`:
        // iterator bindings are: `const/var iter = [try] <recv>.<iter-method>()`
        // We detect at the position of the method name.
        if (tags[t] != .identifier) continue;
        if (!isIteratorMethod(tree.tokenSlice(t))) continue;
        if (t == 0 or tags[t - 1] != .period) continue;
        if (t + 1 > last or tags[t + 1] != .l_paren) continue;
        if (t + 2 > last or tags[t + 2] != .r_paren) continue;

        // Walk backward from `t-2` (the `.`) to find the binding `const/var iter =`.
        // Also extract the receiver name (the identifier before the `.`).
        const dot_pos: Ast.TokenIndex = t - 1;
        if (dot_pos == 0) continue;
        // The receiver is the identifier at `t-2`.
        if (tags[t - 2] != .identifier) continue;
        const recv_name = tree.tokenSlice(t - 2);

        // Walk backward from `t-3` to find `= recv .` and then `const/var iter =`.
        // Simple check: `t-2` is `recv`, `t-1` is `.`, `t` is method, so the `=` is
        // before `recv`. Walk backward from `t-3`.
        var i: Ast.TokenIndex = t - 3;
        // Walk past any `try` keyword.
        if (tags[i] == .keyword_try) {
            if (i == 0) continue;
            i -= 1;
        }
        // Now `i` should be at `=`.
        if (tags[i] != .equal) continue;
        if (i == 0) continue;
        const j = i - 1; // should be the iter name
        if (tags[j] != .identifier) continue;
        const iter_name = tree.tokenSlice(j);
        if (j == 0) continue;
        const before_iter = tags[j - 1];
        if (before_iter != .keyword_const and before_iter != .keyword_var) continue;

        // `iter_name` is the iterator variable, `recv_name` is the map.
        // Find the `;` that ends the iterator binding statement.
        const semi = findStmtSemicolon(tags, t, last) orelse continue;

        // Scan from `semi+1` to `last` for `while (<iter_name>.next())`.
        try scanForWhileLoop(gpa, tree, tags, iter_name, recv_name, semi + 1, last, problems);
    }
}

/// Scan from `scan_start` to `last` for `while (<iter>.next()) |...| { ... <recv>.<mutate> ... }`.
fn scanForWhileLoop(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    iter_name: []const u8,
    recv_name: []const u8,
    scan_start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    var t: Ast.TokenIndex = scan_start;
    while (t + 7 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }

        if (tags[t] != .keyword_while) continue;
        if (t + 1 > last or tags[t + 1] != .l_paren) continue;

        const cond_lp = t + 1;
        const cond_rp = matchParen(tags, cond_lp, last) orelse continue;

        // The condition must be exactly `(<iter>.next())`.
        // Tokens inside: iter . next ( )  → 5 tokens → cond_rp = cond_lp + 6.
        if (cond_rp != cond_lp + 6) continue;
        if (tags[cond_lp + 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(cond_lp + 1), iter_name)) continue;
        if (tags[cond_lp + 2] != .period) continue;
        if (tags[cond_lp + 3] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(cond_lp + 3), "next")) continue;
        if (tags[cond_lp + 4] != .l_paren) continue;
        if (tags[cond_lp + 5] != .r_paren) continue;

        // After cond_rp, skip optional `: (continue_expr)` then optional `|capture|`.
        var body_start = cond_rp + 1;
        if (body_start <= last and tags[body_start] == .colon) {
            if (body_start + 1 <= last and tags[body_start + 1] == .l_paren) {
                const cont_rp = matchParen(tags, body_start + 1, last) orelse continue;
                body_start = cont_rp + 1;
            }
        }
        if (body_start <= last and tags[body_start] == .pipe) {
            body_start += 1;
            while (body_start <= last and tags[body_start] != .pipe) : (body_start += 1) {}
            if (body_start > last) continue;
            body_start += 1;
        }
        if (body_start > last or tags[body_start] != .l_brace) continue;
        const body_end = matchBrace(tags, body_start, last) orelse continue;

        // Scan the while body for `<recv>.<mutate>(` at depth 0.
        const mutate_tok = findReceiverMutate(tree, tags, body_start + 1, body_end - 1, recv_name) orelse continue;

        // Fire.
        const msg = try std.fmt.allocPrint(
            gpa,
            "`{s}.{s}(...)` modifies the map while `{s}` is iterating over it — the iterator cursor is now undefined.  Collect items to change into a separate list first.",
            .{ recv_name, tree.tokenSlice(mutate_tok), iter_name },
        );
        errdefer gpa.free(msg);
        try problems.append(gpa, .{
            .rule_id = "hashmap-iter-mutation",
            .severity = .@"error",
            .start = Pos.fromTokenStart(tree, mutate_tok),
            .end = Pos.fromTokenEnd(tree, mutate_tok),
            .message = msg,
        });
        // One report per while loop is enough.
        t = body_end;
    }
}

/// Scan `[start, last]` for `<recv>.<mutate>(` at the top-level block
/// depth (lexical nesting 0).  Skips nested `{...}` blocks, `defer`/
/// `errdefer` statements, and `fn` bodies.  Returns the token index
/// of the mutate method name on success.
fn findReceiverMutate(
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    recv: []const u8,
) ?Ast.TokenIndex {
    if (start > last) return null;
    var t: Ast.TokenIndex = start;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] == .l_brace) {
            t = matchBrace(tags, t, last) orelse return null;
            continue;
        }
        if (tags[t] == .r_brace) return null;
        if (tags[t] == .keyword_defer or tags[t] == .keyword_errdefer) {
            t = skipDeferStmt(tags, t, last) orelse return null;
            continue;
        }
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), recv)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .l_paren) continue;
        if (isMutateMethod(tree.tokenSlice(t + 2))) return t + 2;
    }
    return null;
}

// ── Tests ──────────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    return testing.runRule(gpa, check, src);
}

const freeProblems = testing.freeProblems;

test "hashmap-iter-mutation: remove during iteration fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo(map: anytype) void {
        \\    var iter = map.iterator();
        \\    while (iter.next()) |entry| {
        \\        if (entry.value_ptr.* == 0)
        \\            _ = map.remove(entry.key_ptr.*);
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("hashmap-iter-mutation", problems.items[0].rule_id);
}

test "hashmap-iter-mutation: put during iteration fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo(map: anytype) !void {
        \\    var iter = map.iterator();
        \\    while (iter.next()) |entry| {
        \\        try map.put(entry.key_ptr.*, entry.value_ptr.* + 1);
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "hashmap-iter-mutation: read-only iteration does NOT fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo(map: anytype) u32 {
        \\    var sum: u32 = 0;
        \\    var iter = map.iterator();
        \\    while (iter.next()) |entry| {
        \\        sum += entry.value_ptr.*;
        \\    }
        \\    return sum;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "hashmap-iter-mutation: mutation on different map does NOT fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo(map: anytype, other: anytype) void {
        \\    var iter = map.iterator();
        \\    while (iter.next()) |entry| {
        \\        _ = other.remove(entry.key_ptr.*);
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "hashmap-iter-mutation: clearAndFree during iteration fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\pub fn foo(map: anytype, alloc: anytype) void {
        \\    var iter = map.keyIterator();
        \\    while (iter.next()) |key| {
        \\        _ = key;
        \\        map.clearAndFree(alloc);
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}
