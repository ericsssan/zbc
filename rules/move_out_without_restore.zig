//! Move-out-without-restore detector — `var X = OBJ.toArrayList(...)`
//! (or similar move-out method that clears OBJ's internal state)
//! followed by a fallible operation on X, without a
//! `defer OBJ.setArrayList(X)` (or equivalent restore) registered
//! between.  On the error path, X is dropped with the partial
//! allocation and OBJ is left holding cleared/stale state — the
//! caller's `OBJ.deinit()` later either leaks or hits a stale ptr.
//!
//! Real-world: ziglang/zig#24452 — `Io.Writer.Allocating.toOwnedSlice*()`
//! fixed exactly this shape (added missing `defer a.setArrayList(list)`).
//! The same shape recurs across the std as
//! `defer self.* = aw.toArrayList()` pairs (array_list.zig:1037,
//! AstGen.zig:11322, Builder.zig:9091, ZonGen.zig:476,574).
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Find `var <X> = <OBJ>.<move-method>(...)` bindings where
//!      move-method ∈ {`toArrayList`, `toOwnedSlice`,
//!      `toOwnedSliceSentinel`, `detach`, `release`}.
//!   3. Within the fn, check for `defer <OBJ>.<restore-method>(<X>)`
//!      (or `defer <OBJ>.* = ...`) AFTER the binding and BEFORE
//!      the next `try` on <X>.
//!   4. If no restore registered AND a fallible op on X follows,
//!      fire.

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
    if (!config_mod.isEnabled(config, .move_out_without_restore)) return;

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
    obj_name: []const u8,
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
        if (tags[t] != .keyword_var) continue;
        if (tags[t + 1] != .identifier) continue;
        // Skip optional type annotation.
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
        var rhs: Ast.TokenIndex = after_name + 1;
        if (rhs <= last and tags[rhs] == .keyword_try) rhs += 1;
        if (rhs + 3 > last) continue;
        if (tags[rhs] != .identifier) continue;
        if (tags[rhs + 1] != .period) continue;
        if (tags[rhs + 2] != .identifier) continue;
        if (tags[rhs + 3] != .l_paren) continue;
        if (!isMoveOutMethod(tree.tokenSlice(rhs + 2))) continue;
        const sc = findStmtSemicolon(tags, rhs + 4, last) orelse continue;
        try bindings.append(gpa, .{
            .x_name = tree.tokenSlice(t + 1),
            .obj_name = tree.tokenSlice(rhs),
            .name_token = t + 1,
            .end_token = sc,
        });
        t = sc;
    }

    for (bindings.items) |b| {
        // Has a restore been registered AFTER the binding?
        if (hasRestoreOf(tree, b.end_token + 1, last, b.obj_name, b.x_name)) continue;
        // Is there a fallible op on X after the binding?
        if (!hasFallibleOnX(tree, b.end_token + 1, last, b.x_name)) continue;
        try report(gpa, problems, tree, b);
    }
}

fn isMoveOutMethod(name: []const u8) bool {
    return std.mem.eql(u8, name, "toArrayList") or
        std.mem.eql(u8, name, "toOwnedSlice") or
        std.mem.eql(u8, name, "toOwnedSliceSentinel") or
        std.mem.eql(u8, name, "detach") or
        std.mem.eql(u8, name, "release");
}

/// True iff `[start, last]` contains `defer <obj>.<restore>(<X>)`
/// or `defer <obj>.* = ...<X>...` (whole-struct restore).
fn hasRestoreOf(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    obj: []const u8,
    x: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > last) return false;
    var t: Ast.TokenIndex = start;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] != .keyword_defer) continue;
        // `defer <obj>.<restore>(<X>)`
        if (tags[t + 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 1), obj)) continue;
        if (tags[t + 2] != .period) continue;
        // `defer <obj>.* = ...`
        if (tags[t + 3] == .asterisk and t + 4 <= last and tags[t + 4] == .equal) {
            return true;
        }
        if (tags[t + 3] != .identifier) continue;
        if (tags[t + 4] != .l_paren) continue;
        if (!isRestoreMethod(tree.tokenSlice(t + 3))) continue;
        if (tags[t + 5] != .identifier) continue;
        if (std.mem.eql(u8, tree.tokenSlice(t + 5), x)) return true;
    }
    return false;
}

fn isRestoreMethod(name: []const u8) bool {
    return std.mem.eql(u8, name, "setArrayList") or
        std.mem.eql(u8, name, "fromArrayList") or
        std.mem.eql(u8, name, "replaceWith") or
        std.mem.eql(u8, name, "restore") or
        std.mem.eql(u8, name, "attach") or
        std.mem.eql(u8, name, "acquire");
}

/// True iff `[start, last]` contains a fallible op on <X> —
/// `try <X>.<method>(` OR `try <something>(<X>...)` shape.
fn hasFallibleOnX(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    x: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > last) return false;
    var t: Ast.TokenIndex = start;
    while (t + 1 <= last) : (t += 1) {
        if (tags[t] != .keyword_try) continue;
        if (tags[t + 1] != .identifier) continue;
        if (std.mem.eql(u8, tree.tokenSlice(t + 1), x)) return true;
    }
    return false;
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
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`var {s} = {s}.toArrayList(...)` (or similar move-out) followed by `try {s}.<fallible>(...)` with no `defer {s}.setArrayList({s});` between — on the error path, {s} is dropped with partial allocation and {s} is left holding cleared/stale state",
        .{ b.x_name, b.obj_name, b.x_name, b.obj_name, b.x_name, b.x_name, b.obj_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "move-out-without-restore",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, b.name_token),
        .end = Pos.fromTokenEnd(tree, b.name_token),
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

test "move-out-without-restore: Allocating.toOwnedSlice* pattern fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Allocating = struct {
        \\    pub fn toArrayList(_: *Allocating) ArrayList { return undefined; }
        \\    pub fn setArrayList(_: *Allocating, _: ArrayList) void {}
        \\};
        \\const ArrayList = struct {
        \\    pub fn toOwnedSlice(_: *ArrayList, _: anytype) ![]u8 { return undefined; }
        \\};
        \\pub fn take(a: *Allocating, gpa: anytype) ![]u8 {
        \\    var list = a.toArrayList();
        \\    return try list.toOwnedSlice(gpa);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
    try std.testing.expectEqualStrings("move-out-without-restore", problems.items[0].rule_id);
}

test "move-out-without-restore: with defer restore doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Allocating = struct {
        \\    pub fn toArrayList(_: *Allocating) ArrayList { return undefined; }
        \\    pub fn setArrayList(_: *Allocating, _: ArrayList) void {}
        \\};
        \\const ArrayList = struct {
        \\    pub fn toOwnedSlice(_: *ArrayList, _: anytype) ![]u8 { return undefined; }
        \\};
        \\pub fn take(a: *Allocating, gpa: anytype) ![]u8 {
        \\    var list = a.toArrayList();
        \\    defer a.setArrayList(list);
        \\    return try list.toOwnedSlice(gpa);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "move-out-without-restore: no fallible op after doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Allocating = struct {
        \\    pub fn toArrayList(_: *Allocating) ArrayList { return undefined; }
        \\};
        \\const ArrayList = struct {
        \\    items: []u8,
        \\};
        \\pub fn peek(a: *Allocating) usize {
        \\    var list = a.toArrayList();
        \\    return list.items.len;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
