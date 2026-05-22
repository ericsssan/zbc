//! Defer-and-errdefer-free-overlap detector — `defer <alloc>.free(X);`
//! (unconditional cleanup) AND an `errdefer { ... <field> = X; ... }`
//! (error path: write `X` into a field) AND a subsequent `try`.
//! On the error path:
//!   1. errdefer fires: frees `self.<field>` (the NEW), sets
//!      `self.<field> = X` (the OLD).
//!   2. defer fires: frees `X` — the value just stored.
//!   → `self.<field>` is now a dangling pointer to freed memory.
//!
//! Real-world: ghostty-org/ghostty#8249 (`Atlas.grow`) — swap-and-
//! resurrect pattern where the defer's free and the errdefer's
//! field-restore land on the same name, leaking through the
//! errdefer's resurrected pointer.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Collect `defer <alloc>.free(<X>);` — track `<X>` names.
//!   3. Look for `errdefer { ... <lhs> = <X>; ... }` blocks
//!      where `<X>` is one of the deferred names AND the
//!      errdefer body also contains a free of a different
//!      receiver (the "free new, restore old" shape).
//!   4. Confirm a `try` appears between the errdefer and the end
//!      of the fn — that's the fallible op that triggers the
//!      double-fire.
//!   5. Fire at the errdefer site.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("problem.zig");
const config_mod = @import("config.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .defer_and_errdefer_free_overlap)) return;

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

    // Collect `defer <alloc>.free(<X>);` deferred names.
    var deferred_frees: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deferred_frees.deinit(gpa);

    var t: Ast.TokenIndex = first;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_defer) continue;
        // Pattern: `defer <alloc> . free ( <X> )`
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .period) continue;
        if (tags[t + 3] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 3), "free")) continue;
        if (tags[t + 4] != .l_paren) continue;
        if (tags[t + 5] != .identifier) continue;
        try deferred_frees.append(gpa, tree.tokenSlice(t + 5));
    }
    if (deferred_frees.items.len == 0) return;

    // Walk for `errdefer { ... }` blocks that contain an
    // assignment `<lhs> = <deferred-name>;` AND a free call
    // (different receiver).
    t = first;
    while (t + 2 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_errdefer) continue;
        // Optional `|err|` capture.
        var body_start: Ast.TokenIndex = t + 1;
        if (body_start <= last and tags[body_start] == .pipe) {
            var p: Ast.TokenIndex = body_start + 1;
            while (p <= last and tags[p] != .pipe) : (p += 1) {}
            if (p > last) continue;
            body_start = p + 1;
        }
        if (body_start > last or tags[body_start] != .l_brace) {
            // Inline form: a single statement.  This rule
            // requires a block form (free + restore is 2+
            // statements).
            continue;
        }
        const body_end = matchBrace(tags, body_start, last) orelse continue;
        const restored = errdeferRestoresDeferredName(tree, body_start + 1, body_end - 1, deferred_frees.items) orelse {
            t = body_end;
            continue;
        };
        if (!errdeferContainsFree(tree, body_start + 1, body_end - 1)) {
            t = body_end;
            continue;
        }
        // Confirm a `try` exists between errdefer and end of fn.
        if (!hasTokenInRange(tags, body_end + 1, last, .keyword_try)) {
            t = body_end;
            continue;
        }
        try report(gpa, problems, tree, t, restored);
        t = body_end;
    }
}

/// True iff the errdefer body contains an assignment
/// `<lhs> = <deferred-name>;` — restoring the to-be-freed name
/// into a field/local.
fn errdeferRestoresDeferredName(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    deferred: []const []const u8,
) ?[]const u8 {
    const tags = tree.tokens.items(.tag);
    if (start > end) return null;
    var t: Ast.TokenIndex = start;
    while (t + 1 <= end) : (t += 1) {
        if (tags[t] != .equal) continue;
        if (t + 1 > end or tags[t + 1] != .identifier) continue;
        const name = tree.tokenSlice(t + 1);
        for (deferred) |d| {
            if (std.mem.eql(u8, d, name)) return d;
        }
    }
    return null;
}

/// True iff the errdefer body contains `<x>.free(...)` or
/// `<x>.destroy(...)`.
fn errdeferContainsFree(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > end) return false;
    var t: Ast.TokenIndex = start;
    while (t + 2 <= end) : (t += 1) {
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .l_paren) continue;
        const m = tree.tokenSlice(t + 1);
        if (std.mem.eql(u8, m, "free") or std.mem.eql(u8, m, "destroy")) return true;
    }
    return false;
}

fn hasTokenInRange(
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    needle: std.zig.Token.Tag,
) bool {
    if (start > end) return false;
    var t: Ast.TokenIndex = start;
    while (t <= end) : (t += 1) {
        if (tags[t] == needle) return true;
    }
    return false;
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
    errdefer_tok: Ast.TokenIndex,
    restored_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`errdefer` body frees the NEW value and restores `{s}` (the OLD value) into a field — but a prior `defer alloc.free({s});` will then ALSO free `{s}` at scope exit, leaving the restored field as a dangling pointer.  Remove the unconditional `defer` and free OLD only on the success path (or move the free into the errdefer body explicitly)",
        .{ restored_name, restored_name, restored_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "defer-and-errdefer-free-overlap",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, errdefer_tok),
        .end = Pos.fromTokenEnd(tree, errdefer_tok),
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

test "defer-and-errdefer-free-overlap: Atlas.grow pattern fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Self = struct {
        \\    data: []u8,
        \\    nodes: std.ArrayList(u8),
        \\    pub fn grow(self: *Self, alloc: std.mem.Allocator) !void {
        \\        const data_old = self.data;
        \\        self.data = try alloc.alloc(u8, 64);
        \\        defer alloc.free(data_old);
        \\        errdefer {
        \\            alloc.free(self.data);
        \\            self.data = data_old;
        \\        }
        \\        try self.nodes.append(alloc, 0);
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
    try std.testing.expectEqualStrings("defer-and-errdefer-free-overlap", problems.items[0].rule_id);
}

test "defer-and-errdefer-free-overlap: errdefer that doesn't restore doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Self = struct {
        \\    data: []u8,
        \\    pub fn grow(self: *Self, alloc: std.mem.Allocator) !void {
        \\        const data_old = self.data;
        \\        self.data = try alloc.alloc(u8, 64);
        \\        defer alloc.free(data_old);
        \\        errdefer alloc.free(self.data);
        \\        _ = try fallible();
        \\    }
        \\};
        \\fn fallible() !void {}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "defer-and-errdefer-free-overlap: no subsequent try doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Self = struct {
        \\    data: []u8,
        \\    pub fn grow(self: *Self, alloc: std.mem.Allocator) void {
        \\        const data_old = self.data;
        \\        self.data = alloc.alloc(u8, 64) catch return;
        \\        defer alloc.free(data_old);
        \\        errdefer {
        \\            alloc.free(self.data);
        \\            self.data = data_old;
        \\        }
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
