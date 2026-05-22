//! ArrayList items-slice rehash detector — `const <X> = <list>.items;`
//! borrows a slice over the list's heap-backed storage.  A
//! subsequent receiver-matched `<list>.<mutate>(...)` call may
//! reallocate the backing storage (when the new length exceeds
//! capacity) — `<X>.ptr` then dangles into freed memory.  A later
//! read or write through `<X>` is a UAF against list storage.
//!
//! Same family as [[hashmap-getptr-rehash]] — the borrow-then-
//! mutate pattern, this time against `std.ArrayList` / `ArrayListUnmanaged`
//! / `BoundedArray`-shaped APIs.  ArrayList's docs explicitly warn
//! that the `.items` slice is invalidated by any capacity-modifying
//! call.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Walk the fn body for `const <X> = <recv>.items;` bindings
//!      where `<recv>` is a single identifier.  `const` only; var
//!      allows reassignment we don't track.
//!   3. From the binding's `;`, scan forward for the first
//!      `<recv>.<mutate-method>(` at the SAME lexical block depth,
//!      skipping nested blocks (catch/if/loop bodies — they don't
//!      always execute) and `defer`/`errdefer` statements
//!      (deferred, not inline).
//!   4. After the mutate, scan for the first use of `<X>` in the
//!      binding's enclosing scope and fire on the use site.
//!
//! Mutate-method allowlist (definitely or likely reallocates):
//!   append / appendSlice / appendNTimes / insert / insertSlice /
//!   addOne / addManyAsSlice / addManyAsArray / resize /
//!   clearAndFree / deinit.
//!
//! Deliberately omitted:
//!   - All `*AssumeCapacity` variants — explicit no-realloc contract.
//!   - `ensureTotalCapacity*` / `ensureUnusedCapacity` — typically
//!     pre-allocation idiom (called BEFORE borrow); FPs would
//!     outweigh real-bug yield.
//!   - `swapRemove` / `orderedRemove` / `pop` — don't reallocate.
//!     The borrowed slice's `.ptr` remains valid (only `.len`
//!     becomes stale, which doesn't UAF).
//!   - `clearRetainingCapacity` — no realloc.

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
    if (!config_mod.isEnabled(config, .arraylist_items_slice)) return;

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
    x_name: []const u8,
    recv_name: []const u8,
    name_token: Ast.TokenIndex,
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
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_const) continue;
        if (tags[t + 1] != .identifier) continue;

        // Optional type annotation.
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

        // RHS must be exactly `<recv> . items ;`.  Single-identifier
        // receiver, no chaining, no slicing, no `&` prefix — those
        // shapes have their own ambiguities and are out of scope
        // until we see them in real bugs.
        const rhs_start: Ast.TokenIndex = after_name + 1;
        if (rhs_start + 3 > last) continue;
        if (tags[rhs_start] != .identifier) continue;
        if (tags[rhs_start + 1] != .period) continue;
        if (tags[rhs_start + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(rhs_start + 2), "items")) continue;
        if (tags[rhs_start + 3] != .semicolon) continue;

        try bindings.append(gpa, .{
            .x_name = tree.tokenSlice(t + 1),
            .recv_name = tree.tokenSlice(rhs_start),
            .name_token = t + 1,
            .end_token = rhs_start + 3,
        });
        t = rhs_start + 3;
    }

    for (bindings.items) |b| {
        const mutate_tok = findReceiverMutate(tree, b.end_token + 1, last, b.recv_name) orelse continue;
        const after_mutate = findStmtSemicolon(tags, mutate_tok, last) orelse continue;
        const use_tok = findIdentUse(tree, after_mutate + 1, last, b.x_name) orelse continue;
        try report(gpa, problems, tree, b, mutate_tok, use_tok);
    }
}

fn isMutateMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "append") or
        std.mem.eql(u8, name, "appendSlice") or
        std.mem.eql(u8, name, "appendNTimes") or
        std.mem.eql(u8, name, "insert") or
        std.mem.eql(u8, name, "insertSlice") or
        std.mem.eql(u8, name, "addOne") or
        std.mem.eql(u8, name, "addManyAsSlice") or
        std.mem.eql(u8, name, "addManyAsArray") or
        std.mem.eql(u8, name, "resize") or
        std.mem.eql(u8, name, "clearAndFree") or
        std.mem.eql(u8, name, "deinit");
}

/// Scan `[start, last]` for the first `<recv>.<mutate-method>(` at
/// the binding's lexical scope.  Stops at the enclosing scope's
/// closing `}`; skips nested blocks (deeper-scope mutates don't
/// always execute); skips `defer`/`errdefer` statements (deferred).
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
        if (isMutateMethodName(tree.tokenSlice(t + 2))) return t + 2;
    }
    return null;
}

/// Find the first identifier whose text equals `name` within the
/// binding's enclosing scope (bounded by the scope's closing `}`).
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

fn skipDeferStmt(
    tags: []const std.zig.Token.Tag,
    kw: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var t: Ast.TokenIndex = kw + 1;
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
        "use of `{s}` after `{s}.{s}(...)` — the slice borrowed from `{s}.items` was invalidated; the call may have reallocated the list's backing storage",
        .{ b.x_name, b.recv_name, mutate_method, b.recv_name },
    );
    errdefer gpa.free(msg);

    const note_label = try std.fmt.allocPrint(
        gpa,
        "borrowed here via `{s}.items`",
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
        .rule_id = "arraylist-items-slice",
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

test "arraylist-items-slice: items then append then use fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn buggy(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
        \\    const items = list.items;
        \\    try list.append(gpa, 1);
        \\    items[0] = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("arraylist-items-slice", problems.items[0].rule_id);
}

test "arraylist-items-slice: use before append doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
        \\    const items = list.items;
        \\    items[0] = 99;
        \\    try list.append(gpa, 1);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "arraylist-items-slice: different receiver doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(a: *std.ArrayList(u32), b: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
        \\    const items = a.items;
        \\    try b.append(gpa, 1);
        \\    items[0] = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "arraylist-items-slice: appendSlice / insert variants caught" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn buggy(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
        \\    const items = list.items;
        \\    try list.appendSlice(gpa, &.{ 1, 2, 3 });
        \\    items[0] = 99;
        \\}
        \\pub fn buggy2(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
        \\    const items = list.items;
        \\    try list.insert(gpa, 0, 99);
        \\    items[0] = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 2), problems.items.len);
}

test "arraylist-items-slice: appendAssumeCapacity does NOT fire (no realloc by contract)" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(list: *std.ArrayList(u32)) void {
        \\    const items = list.items;
        \\    list.appendAssumeCapacity(99);
        \\    items[0] = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "arraylist-items-slice: ensureUnusedCapacity does NOT fire (pre-alloc idiom)" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
        \\    const items = list.items;
        \\    try list.ensureUnusedCapacity(gpa, 10);
        \\    items[0] = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "arraylist-items-slice: mutate inside errdefer is skipped" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
        \\    const items = list.items;
        \\    errdefer list.deinit(gpa);
        \\    items[0] = 99;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "arraylist-items-slice: mutate inside catch block is skipped" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
        \\    const items = list.items;
        \\    doSomething() catch {
        \\        list.deinit(gpa);
        \\        return;
        \\    };
        \\    items[0] = 99;
        \\}
        \\fn doSomething() !void {}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "arraylist-items-slice: shadowed loop capture in sibling scope doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(list: *std.ArrayList(u32), gpa: std.mem.Allocator) !void {
        \\    while (list.items.len > 0) {
        \\        const items = list.items;
        \\        _ = items[0];
        \\        try list.append(gpa, 1);
        \\    }
        \\    var arr: [3]u32 = .{ 1, 2, 3 };
        \\    for (arr[0..]) |items| {
        \\        _ = items;
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
