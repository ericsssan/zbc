//! HashMap getPtr-rehash detector — `const <X> = <map>.getPtr(...);`
//! (or `getOrPut`, `getOrPutValue`, etc.) borrows a pointer into the
//! map's internal storage.  A subsequent `<map>.put(...)` /
//! `.remove(...)` / `.fetchPut(...)` on the SAME receiver MAY rehash
//! the table — invalidating `<X>` (and any sub-pointer like
//! `gop.value_ptr` / `gop.key_ptr`).  A later read of `<X>` after
//! that mutation point is a use-after-free against table storage.
//!
//! Zig std's HashMap pointer-stability rules are documented:
//! pointers returned by `getPtr` / `getOrPut.value_ptr` are valid
//! ONLY until the next call that may grow the table.  This is the
//! single most common Zig footgun on hashmaps — the borrow is
//! invisibly invalidated and the failure mode is intermittent
//! (only fires when the put happens to trigger a resize).
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Walk the fn body for `const <X> = [try] [<recv>.]<borrow-method>(`
//!      bindings where `borrow-method` is in the allowlist below.
//!      Only `const` bindings — `var` introduces reassignment we
//!      don't track.
//!   3. Capture `<X>`, `<recv>` (the leading identifier before the
//!      `.borrow-method`), and the statement-terminating `;`.
//!   4. From the binding's `;`, scan forward for a call shaped
//!      `<recv>.<mutate-method>(` (receiver-matched).
//!   5. From that mutation point, scan forward for any token mention
//!      of `<X>` at fn scope — fire at the use site.
//!
//! Mutate-method allowlist (definitely invalidates):
//!   put / putAssumeCapacity / putNoClobber / remove / removeByPtr /
//!   fetchPut / fetchRemove / swapRemove.
//!
//! Deliberately omitted (typically used to PRE-allocate, calling
//! them AFTER a borrow is its own bug but a rare one):
//!   ensureTotalCapacity / ensureUnusedCapacity / clearAndFree /
//!   clearRetainingCapacity.

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
    if (!config_mod.isEnabled(config, .hashmap_getptr_rehash)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        if (returnsType(tree, node)) continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, body, problems);
    }
}

const Binding = struct {
    /// Identifier text of the borrowed local (`<X>`).
    x_name: []const u8,
    /// Identifier text of the leading receiver (`<recv>`).
    recv_name: []const u8,
    /// Token index of the bound name — anchor for "borrow site" note.
    name_token: Ast.TokenIndex,
    /// Token of the binding's terminating semicolon — scan starts
    /// immediately after.
    end_token: Ast.TokenIndex,
};

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var bindings: std.ArrayListUnmanaged(Binding) = .empty;
    defer bindings.deinit(gpa);

    var t: Ast.TokenIndex = first;
    while (t + 5 <= last) : (t += 1) {
        // Skip past nested fns so inner bindings aren't double-scoped
        // through the outer fn.
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_const) continue;
        if (tags[t + 1] != .identifier) continue;

        // Skip optional `: T` type annotation.
        var after_name: Ast.TokenIndex = t + 2;
        if (after_name <= last and tags[after_name] == .colon) {
            var d: u32 = 0;
            while (after_name <= last) : (after_name += 1) {
                switch (tags[after_name]) {
                    .l_paren, .l_brace, .l_bracket => d += 1,
                    .r_paren, .r_brace, .r_bracket => if (d > 0) {
                        d -= 1;
                    },
                    .equal => if (d == 0) break,
                    else => {},
                }
            }
        }
        if (after_name > last or tags[after_name] != .equal) continue;

        // Optional `try`.
        var rhs_start: Ast.TokenIndex = after_name + 1;
        if (rhs_start <= last and tags[rhs_start] == .keyword_try) rhs_start += 1;
        if (rhs_start + 3 > last) continue;
        // Need `<recv> . <method> (`.  `<recv>` is a single identifier
        // (a local map handle) — that's the common case and keeps the
        // detector tight.  Map-of-map (`outer.inner.getPtr(...)`)
        // borrows are rare and out of scope.
        if (tags[rhs_start] != .identifier) continue;
        if (tags[rhs_start + 1] != .period) continue;
        if (tags[rhs_start + 2] != .identifier) continue;
        if (tags[rhs_start + 3] != .l_paren) continue;
        if (!isBorrowMethodName(tree.tokenSlice(rhs_start + 2))) continue;

        const sc = findStmtSemicolon(tags, rhs_start + 4, last) orelse continue;
        try bindings.append(gpa, .{
            .x_name = tree.tokenSlice(t + 1),
            .recv_name = tree.tokenSlice(rhs_start),
            .name_token = t + 1,
            .end_token = sc,
        });
        t = sc;
    }

    for (bindings.items) |b| {
        // Find the first receiver-matched mutate call after the
        // binding's `;`.
        const mutate_tok = findReceiverMutate(tree, b.end_token + 1, last, b.recv_name) orelse continue;
        // After the mutate call's closing `)`, find any token use of
        // `<X>` — that's the UAF site.
        const after_mutate = stmtEndAfter(tags, mutate_tok, last) orelse continue;
        const use_tok = findIdentUse(tree, after_mutate + 1, last, b.x_name) orelse continue;
        try report(gpa, problems, tree, b, mutate_tok, use_tok);
    }
}

fn isBorrowMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "getPtr") or
        std.mem.eql(u8, name, "getOrPut") or
        std.mem.eql(u8, name, "getOrPutValue") or
        std.mem.eql(u8, name, "getOrPutAssumeCapacity") or
        std.mem.eql(u8, name, "getOrPutAdapted");
}

fn isMutateMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "put") or
        std.mem.eql(u8, name, "putAssumeCapacity") or
        std.mem.eql(u8, name, "putNoClobber") or
        std.mem.eql(u8, name, "putNoClobberAssumeCapacity") or
        std.mem.eql(u8, name, "remove") or
        std.mem.eql(u8, name, "removeByPtr") or
        std.mem.eql(u8, name, "fetchPut") or
        std.mem.eql(u8, name, "fetchRemove") or
        std.mem.eql(u8, name, "swapRemove");
}

/// Scan `[start, last]` for the first `<recv>.<mutate-method>(` at
/// the SAME lexical block depth as `start`.  Mutates nested inside
/// `catch { ... }` / `if { ... }` / loop bodies are skipped — they
/// don't always execute, and the use that follows is on the
/// non-mutating path.  Stops at the binding's enclosing closing `}`
/// — any reference past that is in a different scope (likely a
/// shadowed loop capture or similar).  These two restrictions are
/// the rule's main precision levers and what keeps FPs near zero on
/// real-world code.
fn findReceiverMutate(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    recv: []const u8,
) ?Ast.TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var t: Ast.TokenIndex = start;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .l_brace) {
            t = matchBrace(tags, t, last) orelse return null;
            continue;
        }
        // A closing `}` at our depth means we've left the binding's
        // enclosing scope — stop.
        if (tags[t] == .r_brace) return null;
        // `defer` / `errdefer` statements register deferred actions
        // — the mutate call inside doesn't execute at this lexical
        // position.  Skip the entire defer/errdefer statement.
        if (tags[t] == .keyword_defer or tags[t] == .keyword_errdefer) {
            t = skipDeferStmt(tags, t, last) orelse return null;
            continue;
        }
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), recv)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .l_paren) continue;
        if (isMutateMethodName(tree.tokenSlice(t + 2))) return t + 2;
    }
    return null;
}

/// Skip past a `defer <expr>;` / `errdefer [|err|] <expr>;` /
/// `defer { ... }` / `errdefer { ... }` statement.  Returns the
/// index of the statement's terminating `;` or matching `}`.
fn skipDeferStmt(
    tags: []const std.zig.Token.Tag,
    kw: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var t: Ast.TokenIndex = kw + 1;
    // Optional `|err|` capture on errdefer.
    if (t <= last and tags[t] == .pipe) {
        t += 1;
        while (t <= last and tags[t] != .pipe) : (t += 1) {}
        if (t > last) return null;
        t += 1;
    }
    if (t > last) return null;
    if (tags[t] == .l_brace) return matchBrace(tags, t, last);
    return findStmtSemicolon(tags, t, last);
}

/// Find the end token of the statement containing `pos` — the next
/// statement-depth `;` at or after `pos`.
fn stmtEndAfter(
    tags: []const std.zig.Token.Tag,
    pos: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    return findStmtSemicolon(tags, pos, last);
}

/// Find the first identifier whose text equals `name` in the
/// binding's enclosing scope.  Stops at the enclosing scope's
/// closing `}` — references past that scope must be a shadowed
/// loop capture / different binding sharing the name.  Allows the
/// use to be inside nested blocks within the binding's scope (a
/// common shape: `try map.put(...); for (...) p.* += 1;`).
fn findIdentUse(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    name: []const u8,
) ?Ast.TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var depth: u32 = 0;
    var t: Ast.TokenIndex = start;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_brace => depth += 1,
            .r_brace => if (depth == 0) return null else {
                depth -= 1;
            },
            .identifier => if (std.mem.eql(u8, tree.tokenSlice(t), name)) return t,
            else => {},
        }
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
    b: Binding,
    mutate_tok: Ast.TokenIndex,
    use_tok: Ast.TokenIndex,
) !void {
    const mutate_method = tree.tokenSlice(mutate_tok);
    const msg = try std.fmt.allocPrint(
        gpa,
        "use of `{s}` after `{s}.{s}(...)` — the borrow into `{s}`'s storage was invalidated; the put/remove may have rehashed the table",
        .{ b.x_name, b.recv_name, mutate_method, b.recv_name },
    );
    errdefer gpa.free(msg);

    const note_label = try std.fmt.allocPrint(
        gpa,
        "borrowed here via `{s}.<borrow-method>()`",
        .{b.recv_name},
    );
    errdefer gpa.free(note_label);

    var notes = try gpa.alloc(problem_mod.Note, 1);
    errdefer gpa.free(notes);
    notes[0] = .{
        .start = Pos.fromTokenStart(tree, b.name_token),
        .end = Pos.fromTokenEnd(tree, b.name_token),
        .label = note_label,
    };

    try problems.append(gpa, .{
        .rule_id = "hashmap-getptr-rehash",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, use_tok),
        .end = Pos.fromTokenEnd(tree, use_tok),
        .message = msg,
        .notes = notes,
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

test "hashmap-getptr-rehash: getPtr then put then use fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn buggy(map: *std.AutoHashMap(u32, u32)) !void {
        \\    const p = map.getPtr(1) orelse return;
        \\    try map.put(2, 20);
        \\    p.* = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("hashmap-getptr-rehash", problems.items[0].rule_id);
}

test "hashmap-getptr-rehash: use before put doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(map: *std.AutoHashMap(u32, u32)) !void {
        \\    const p = map.getPtr(1) orelse return;
        \\    p.* = 99;
        \\    try map.put(2, 20);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "hashmap-getptr-rehash: different receiver doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(a: *std.AutoHashMap(u32, u32), b: *std.AutoHashMap(u32, u32)) !void {
        \\    const p = a.getPtr(1) orelse return;
        \\    try b.put(2, 20);
        \\    p.* = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "hashmap-getptr-rehash: getOrPut then put then field use fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn buggy(map: *std.AutoHashMap(u32, u32)) !void {
        \\    const gop = try map.getOrPut(1);
        \\    try map.put(2, 20);
        \\    gop.value_ptr.* = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "hashmap-getptr-rehash: remove also invalidates" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn buggy(map: *std.AutoHashMap(u32, u32)) !void {
        \\    const p = map.getPtr(1) orelse return;
        \\    _ = map.remove(2);
        \\    p.* = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "hashmap-getptr-rehash: non-mutating get doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(map: *std.AutoHashMap(u32, u32)) !void {
        \\    const p = map.getPtr(1) orelse return;
        \\    _ = map.get(2);
        \\    p.* = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "hashmap-getptr-rehash: ensureCapacity is NOT in the mutate list (deliberate)" {
    // ensureTotalCapacity/ensureUnusedCapacity DO invalidate, but
    // they're almost always the pre-allocation idiom — flagging them
    // would cost more in FPs than the real-bug yield.  Document this
    // by asserting the call is left alone here.
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(map: *std.AutoHashMap(u32, u32)) !void {
        \\    const p = map.getPtr(1) orelse return;
        \\    try map.ensureUnusedCapacity(10);
        \\    p.* = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "hashmap-getptr-rehash: mutate inside catch block (diverges) is skipped" {
    // Real-world FP shape from bun/src/md/helpers.zig — the
    // `removeByPtr` is inside a `catch { ... return ...; }` so the
    // subsequent `gop.value_ptr.* = ...` is only reached on the
    // SUCCESS path of the preceding op, where no mutate happened.
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(map: *std.StringHashMap(u32), key: []const u8, dupe_ok: bool) []const u8 {
        \\    const gop = map.getOrPut(key) catch return key;
        \\    if (!gop.found_existing) {
        \\        gop.key_ptr.* = if (dupe_ok) key else blk: {
        \\            map.removeByPtr(gop.key_ptr);
        \\            break :blk key;
        \\        };
        \\        gop.value_ptr.* = 0;
        \\    }
        \\    return key;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "hashmap-getptr-rehash: use of same-name identifier in a SIBLING scope doesn't fire" {
    // Real-world FP shape from tigerbeetle/src/aof.zig — `const
    // entry = entries_by_parent.getPtr(...)` is scoped to the while
    // loop body; line 758 mutates the same map; then OUTSIDE that
    // while loop, an unrelated `while ... |entry|` loop binds a
    // different `entry`.  The detector must stop scanning at the
    // binding's enclosing `}` to avoid connecting the borrow to the
    // shadowed loop capture.
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(map: *std.AutoHashMap(u32, u32)) !void {
        \\    while (map.count() > 0) {
        \\        const entry = map.getPtr(1) orelse unreachable;
        \\        _ = entry.*;
        \\        _ = map.remove(2);
        \\    }
        \\    var items: [3]u32 = .{ 1, 2, 3 };
        \\    for (items[0..]) |entry| {
        \\        _ = entry;
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "hashmap-getptr-rehash: mutate inside errdefer (deferred) is skipped" {
    // Real-world FP shape from
    // ghostty/src/terminal/tmux/viewer.zig:1145 — the `swapRemove`
    // is registered via `errdefer`, so it doesn't execute at this
    // lexical point.  The use of `gop.value_ptr.*` happens on the
    // success path before any errdefer fires.
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(map: *std.AutoHashMap(u32, u32)) !void {
        \\    const gop = try map.getOrPut(1);
        \\    if (gop.found_existing) return;
        \\    errdefer _ = map.remove(1);
        \\    gop.value_ptr.* = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "hashmap-getptr-rehash: var binding (could be reassigned) is skipped" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(map: *std.AutoHashMap(u32, u32)) !void {
        \\    var p = map.getPtr(1) orelse return;
        \\    try map.put(2, 20);
        \\    p = map.getPtr(2) orelse return;
        \\    p.* = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
