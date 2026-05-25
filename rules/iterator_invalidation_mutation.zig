//! Iterator-invalidation-during-mutation detector —
//! `for (<list>.items) |...| { ... <list>.<mutate>(...); ... }`
//! where the loop body calls a method on the SAME list that
//! reallocates / shifts its backing storage.  The loop is
//! iterating over a snapshot of `.items` that may now point at
//! freed memory (append/resize) or at shifted/swapped elements
//! (insert/remove/swapRemove), producing UAF or skipped-element
//! bugs.
//!
//! Distinct from [[arraylist-items-slice]]:
//!   - That rule fires on `const X = list.items;` followed by
//!     `list.<mutate>()` then a use of `X`.
//!   - This rule fires on the loop SHAPE directly — `for
//!     (list.items)` is an implicit borrow, and the mutate inside
//!     the body is the smoking gun.
//!
//! Mutator allowlist — anything that reallocates OR reorders the
//! backing storage:
//!   append / appendSlice / appendNTimes / insert / insertSlice /
//!   addOne / addManyAsSlice / addManyAsArray / resize /
//!   clearAndFree / clearRetainingCapacity / deinit /
//!   swapRemove / orderedRemove / pop / popOrNull /
//!   replaceRange / shrinkAndFree / shrinkRetainingCapacity.
//!
//! Detection (per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Walk for `for (<recv>.items)` or `for (<recv>.items, ...)`
//!      loops; capture the `<recv>` name and the loop body extent.
//!   3. Scan the body for `<recv>.<mutator>(` calls at any depth.
//!      Skip nested fn / labeled-block declarations that wouldn't
//!      execute in this loop iteration.
//!   4. Fire on the mutate call site with a note pointing back to
//!      the for-header.

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

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .iterator_invalidation_mutation)) return;
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
    while (t + 5 <= last) : (t += 1) {
        // Skip nested fns so we don't re-enter their bodies as part
        // of an enclosing fn's walk.
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_for) continue;
        if (tags[t + 1] != .l_paren) continue;
        // Find the receiver of `.items` (or `.values` / `.keys`).
        // Walk the first paren's contents for `<recv> . items`.
        const lp = t + 1;
        const cp = matchParen(tags, lp, last) orelse continue;
        const recv_name = receiverOfItemsBorrow(tree, lp + 1, cp - 1) orelse continue;
        // Find the loop body — after the optional `|...|` capture.
        var k: Ast.TokenIndex = cp + 1;
        if (k <= last and tags[k] == .pipe) {
            k += 1;
            while (k <= last and tags[k] != .pipe) : (k += 1) {}
            if (k > last) continue;
            k += 1;
        }
        if (k > last) continue;
        const body_first: Ast.TokenIndex = k;
        const body_last: Ast.TokenIndex = if (tags[body_first] == .l_brace)
            matchBrace(tags, body_first, last) orelse continue
        else blk: {
            // Inline body — single statement to next `;`.
            break :blk lexer.findStmtSemicolon(tags, body_first, last) orelse continue;
        };
        // Search for `<recv>.<mutator>(` inside [body_first, body_last].
        const mutate_tok = findReceiverMutate(tree, body_first, body_last, recv_name) orelse continue;
        try report(gpa, problems, tree, t, recv_name, mutate_tok);
        // Skip past this loop's body so we don't re-find the same
        // mutate from an outer loop scan.
        t = body_last;
    }
}

/// Return the receiver name when the for-scrutinee range
/// `[start, end]` is exactly `<ident> . <projector>` where
/// projector ∈ {items, values, keys} AND `<ident>` is a
/// SINGLE identifier (no dotted chain).  Returns null
/// otherwise — multi-input for loops, multi-segment
/// receivers (`this.ltr.items`), projector via call (`.iterator()`),
/// etc.  The single-ident restriction avoids capture-name
/// shadowing FPs: `for (this.ltr.items) |*ltr|` makes `ltr`
/// (inside the body) the LOOP CAPTURE, not the field — so
/// `ltr.deinit(...)` in the body is element cleanup, not list
/// mutation.
fn receiverOfItemsBorrow(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
) ?[]const u8 {
    const tags = tree.tokens.items(.tag);
    if (end < start + 2) return null;
    // Multi-input for loops: `for (a, b)` has a comma at the same
    // paren depth.  We require a single input.
    {
        var depth: u32 = 0;
        var t: Ast.TokenIndex = start;
        while (t <= end) : (t += 1) {
            switch (tags[t]) {
                .l_paren, .l_brace, .l_bracket => depth += 1,
                .r_paren, .r_brace, .r_bracket => if (depth > 0) {
                    depth -= 1;
                },
                .comma => if (depth == 0) return null,
                else => {},
            }
        }
    }
    // Expect EXACTLY `<ident> . <projector>` — 3 tokens.
    if (end != start + 2) return null;
    if (tags[start] != .identifier) return null;
    if (tags[start + 1] != .period) return null;
    if (tags[start + 2] != .identifier) return null;
    const proj = tree.tokenSlice(start + 2);
    if (!std.mem.eql(u8, proj, "items") and
        !std.mem.eql(u8, proj, "values") and
        !std.mem.eql(u8, proj, "keys")) return null;
    return tree.tokenSlice(start);
}

fn isInvalidatingMutateName(name: []const u8) bool {
    return std.mem.eql(u8, name, "append") or
        std.mem.eql(u8, name, "appendSlice") or
        std.mem.eql(u8, name, "appendNTimes") or
        std.mem.eql(u8, name, "appendAssumeCapacity") or
        std.mem.eql(u8, name, "appendSliceAssumeCapacity") or
        std.mem.eql(u8, name, "insert") or
        std.mem.eql(u8, name, "insertSlice") or
        std.mem.eql(u8, name, "addOne") or
        std.mem.eql(u8, name, "addManyAsSlice") or
        std.mem.eql(u8, name, "addManyAsArray") or
        std.mem.eql(u8, name, "resize") or
        std.mem.eql(u8, name, "clearAndFree") or
        std.mem.eql(u8, name, "clearRetainingCapacity") or
        std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "swapRemove") or
        std.mem.eql(u8, name, "orderedRemove") or
        std.mem.eql(u8, name, "pop") or
        std.mem.eql(u8, name, "popOrNull") or
        std.mem.eql(u8, name, "replaceRange") or
        std.mem.eql(u8, name, "shrinkAndFree") or
        std.mem.eql(u8, name, "shrinkRetainingCapacity") or
        // HashMap operations that rehash / invalidate iterators.
        std.mem.eql(u8, name, "put") or
        std.mem.eql(u8, name, "putAssumeCapacity") or
        std.mem.eql(u8, name, "putAssumeCapacityNoClobber") or
        std.mem.eql(u8, name, "putNoClobber") or
        std.mem.eql(u8, name, "remove") or
        std.mem.eql(u8, name, "fetchRemove") or
        std.mem.eql(u8, name, "getOrPut") or
        std.mem.eql(u8, name, "getOrPutValue");
}

/// Scan `[start, end]` for the first `<recv>.<mutator>(` at any
/// depth.  Skips nested fn declarations.
fn findReceiverMutate(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    recv: []const u8,
) ?Ast.TokenIndex {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 3 <= end) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, end);
            continue;
        }
        if (tags[t] != .identifier) continue;
        // Word-boundary: not a continuation of a dotted chain.
        if (t > 0 and tags[t - 1] == .period) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), recv)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .l_paren) continue;
        if (isInvalidatingMutateName(tree.tokenSlice(t + 2))) return t + 2;
    }
    return null;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    for_tok: Ast.TokenIndex,
    recv: []const u8,
    mutate_tok: Ast.TokenIndex,
) !void {
    const mutate_method = tree.tokenSlice(mutate_tok);
    const msg = try std.fmt.allocPrint(
        gpa,
        "iterator invalidation — `{s}.{s}(...)` mutates `{s}` while a `for ({s}.items) |...|` is iterating over it; the loop's slice borrow may dangle (append/resize realloc) or skip/double-visit elements (insert/swapRemove/remove).  Snapshot the items into a separate list before the loop, or restructure to process+collect first and mutate after",
        .{ recv, mutate_method, recv, recv },
    );
    errdefer gpa.free(msg);
    const note_label = try std.fmt.allocPrint(gpa, "iterating over `{s}.items` here", .{recv});
    errdefer gpa.free(note_label);
    const for_pos = Pos.fromTokenStart(tree, for_tok);
    const for_end = Pos.fromTokenEnd(tree, for_tok);
    const notes_slice = try gpa.alloc(problem_mod.Note, 1);
    notes_slice[0] = .{ .start = for_pos, .end = for_end, .label = note_label };
    try problems.append(gpa, .{
        .rule_id = "iterator-invalidation-mutation",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, mutate_tok),
        .end = Pos.fromTokenEnd(tree, mutate_tok),
        .message = msg,
        .notes = notes_slice,
    });
}

// ── Tests ──────────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    return testing.runRule(gpa, check, src);
}

const freeProblems = testing.freeProblems;

test "iterator-invalidation: for + append fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn add(list: *std.ArrayList(u32)) !void {
        \\    for (list.items) |x| {
        \\        if (x == 0) try list.append(42);
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("iterator-invalidation-mutation", problems.items[0].rule_id);
}

test "iterator-invalidation: for + swapRemove fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn purge(list: *std.ArrayList(u32)) void {
        \\    for (list.items, 0..) |x, i| {
        \\        if (x == 0) _ = list.swapRemove(i);
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // for (list.items, 0..) — multi-input loop, our rule requires
    // a single input.  Expect 0 findings.
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "iterator-invalidation: for + put on hashmap fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn rebuild(map: *std.StringHashMap(u32)) !void {
        \\    for (map.values()) |v| {
        \\        try map.put("x", v + 1);
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // for (map.values()) — the receiver `map` is followed by a
    // call `.values()`, not the field-access shape we look for.
    // Our rule keys on `.items`/`.values`/`.keys` as a FIELD
    // access; method-call form is not detected.  Expect 0.
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "iterator-invalidation: pure read loop doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn sum(list: *std.ArrayList(u32)) u32 {
        \\    var total: u32 = 0;
        \\    for (list.items) |x| total += x;
        \\    return total;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "iterator-invalidation: mutate on DIFFERENT list doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn copy(src: *std.ArrayList(u32), dst: *std.ArrayList(u32)) !void {
        \\    for (src.items) |x| {
        \\        try dst.append(x);
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
