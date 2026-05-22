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

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("../lexer.zig");
const local = @import("../local.zig");
const query = @import("../query.zig");
const problem_mod = @import("../problem.zig");
const testing = @import("../testing.zig");
const config_mod = @import("../config.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const Atom = query.Atom;
const R = "move-out-without-restore";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .move_out_without_restore)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = lexer.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        try checkFn(gpa, tree, fn_entry.proto, fn_entry.body, problems);
    }
}

const MoveBinding = struct {
    x_name: []const u8,
    obj_name: []const u8,
    name_token: Ast.TokenIndex,
    /// Token index of the binding's terminating `;`.
    end_token: Ast.TokenIndex,
};

fn checkFn(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    proto: Ast.full.FnProto,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    var bindings = try local.build(gpa, tree, proto, body);
    defer bindings.deinit();

    var moves: std.ArrayListUnmanaged(MoveBinding) = .empty;
    defer moves.deinit(gpa);

    // Find `var X = <obj>.<moveMethod>(...)` bindings.  Move-out
    // methods clear OBJ's internal state — that's why a restore
    // matters on the error path.
    for (bindings.items) |b| {
        if (b.is_const) continue; // restore-pairing only matters for var
        if (b.origin == .param) continue;
        const c = b.asCall() orelse continue;
        const method = c.method orelse continue;
        if (!isMoveOutMethod(method)) continue;
        moves.append(gpa, .{
            .x_name = b.name,
            .obj_name = c.receiver,
            .name_token = b.name_token,
            // local.Binding.rhs_last is the token before `;`, so the
            // `;` is at rhs_last + 1.
            .end_token = b.rhs_last + 1,
        }) catch return;
    }
    if (moves.items.len == 0) return;

    const last = tree.lastToken(body);
    for (moves.items) |m| {
        if (m.end_token >= last) continue;
        if (hasRestoreOf(tree, m.end_token + 1, last, m.obj_name, m.x_name)) continue;
        if (!hasFallibleOnX(tree, m.end_token + 1, last, m.x_name)) continue;
        try report(gpa, problems, tree, m);
    }
}

fn isMoveOutMethod(name: []const u8) bool {
    return std.mem.eql(u8, name, "toArrayList") or
        std.mem.eql(u8, name, "toOwnedSlice") or
        std.mem.eql(u8, name, "toOwnedSliceSentinel") or
        std.mem.eql(u8, name, "detach") or
        std.mem.eql(u8, name, "release");
}

fn isRestoreMethod(name: []const u8) bool {
    return std.mem.eql(u8, name, "setArrayList") or
        std.mem.eql(u8, name, "fromArrayList") or
        std.mem.eql(u8, name, "replaceWith") or
        std.mem.eql(u8, name, "restore") or
        std.mem.eql(u8, name, "attach") or
        std.mem.eql(u8, name, "acquire");
}

/// True iff `[start, last]` contains `defer <obj>.<restore>(<x>)`
/// OR `defer <obj>.* = ...` (whole-struct restore).  Both patterns
/// are built at runtime since `<obj>` and `<x>` are dynamic.
fn hasRestoreOf(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    obj: []const u8,
    x: []const u8,
) bool {
    // `defer <obj>.* = ...` — whole-struct assignment restore.
    const restore_assign = [_]Atom{
        .{ .tok = .keyword_defer },
        .{ .text = obj },
        .{ .tok = .period_asterisk },
        .{ .tok = .equal },
    };
    if (query.anyMatchAnywhere(tree, &restore_assign, start, last, null)) return true;

    // `defer <obj>.<restoreMethod>(<x>...)`.
    const restore_call = [_]Atom{
        .{ .tok = .keyword_defer },
        .{ .text = obj },
        .{ .tok = .period },
        .{ .pred = isRestoreMethod },
        .{ .tok = .l_paren },
        .{ .text = x },
    };
    return query.anyMatchAnywhere(tree, &restore_call, start, last, null);
}

/// True iff `[start, last]` contains `try <x>` — any fallible op on X.
fn hasFallibleOnX(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    x: []const u8,
) bool {
    const fallible = [_]Atom{
        .{ .tok = .keyword_try },
        .{ .text = x },
    };
    return query.anyMatchAnywhere(tree, &fallible, start, last, null);
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    m: MoveBinding,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`var {s} = {s}.toArrayList(...)` (or similar move-out) followed by `try {s}.<fallible>(...)` with no `defer {s}.setArrayList({s});` between — on the error path, {s} is dropped with partial allocation and {s} is left holding cleared/stale state",
        .{ m.x_name, m.obj_name, m.x_name, m.obj_name, m.x_name, m.x_name, m.obj_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, m.name_token),
        .end = Pos.fromTokenEnd(tree, m.name_token),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "Allocating.toOwnedSlice* pattern fires" {
    try testing.expectFires(check, R,
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
    );
}

test "with defer restore doesn't fire" {
    try testing.expectNoFire(check,
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
    );
}

test "no fallible op after doesn't fire" {
    try testing.expectNoFire(check,
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
    );
}
