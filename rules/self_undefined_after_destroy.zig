//! `<alloc>.destroy(<X>);` immediately followed by a write through
//! `<X>` — `<X>.* = ...;` or `<X>.<field> = ...;` (typically `<X>.*
//! = undefined;`).  The write goes through a now-dangling pointer.
//!
//! Real-world: tigerbeetle/tigerbeetle#2687 — inverted TigerStyle
//! invariant.  The correct order is `<X>.* = undefined; destroy(X);`
//! (overwrite-then-free, so the freed memory holds canary bytes);
//! this rule catches the inversion.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Walk for `<alloc>.destroy(<X>);` and `<alloc>.free(<X>);`
//!      calls where `<X>` is a single bare identifier.
//!   3. From the destroy's `;`, scan forward at the same lexical
//!      block depth (skip nested blocks, defer/errdefer) for either:
//!        - `<X> = ...` — `<X>` is now a different pointer → stop
//!        - `<X>.* = ...` — UAF write → FIRE
//!        - `<X>.<field> = ...` — UAF write → FIRE
//!        - `<alloc>.destroy(<X>)` / `<alloc>.free(<X>)` — defensive
//!          stop (likely a different scope or refactoring artifact)
//!        - End of enclosing scope (`}`) → stop
//!   4. Fire on the write site.

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
    if (!config_mod.isEnabled(config, .self_undefined_after_destroy)) return;

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

    var t: Ast.TokenIndex = first;
    while (t + 4 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] == .keyword_defer or tags[t] == .keyword_errdefer) {
            t = skipDeferStmt(tags, t, last) orelse last;
            continue;
        }
        // Pattern: `.destroy(<X>)` or `.free(<X>)` where `<X>` is a
        // bare identifier and the call is preceded by `.` (method
        // invocation on an allocator).
        if (tags[t] != .identifier) continue;
        if (t == 0 or tags[t - 1] != .period) continue;
        const method = tree.tokenSlice(t);
        if (!std.mem.eql(u8, method, "destroy") and !std.mem.eql(u8, method, "free")) continue;
        if (tags[t + 1] != .l_paren) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .r_paren) continue;
        const x_name = tree.tokenSlice(t + 2);
        // Exclude self-allocator-named references — e.g.,
        // `allocator.destroy(allocator)` would be nonsense.
        if (t >= 2 and tags[t - 2] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t - 2), x_name))
        {
            continue;
        }
        const sc = findStmtSemicolon(tags, t + 4, last) orelse continue;
        const write_tok = findWriteThroughX(tree, sc + 1, last, x_name) orelse {
            t = sc;
            continue;
        };
        try report(gpa, problems, tree, write_tok, x_name, method);
        t = sc;
    }
}

/// Scan `[start, last]` for the first write through `<X>` —
/// `<X>.* = ...` or `<X>.<field> = ...`.  Stops at enclosing scope
/// (`}`), at reassignment of `<X>`, at another destroy of `<X>`,
/// and skips nested blocks / defer / errdefer.
fn findWriteThroughX(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    x_name: []const u8,
) ?Ast.TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var t: Ast.TokenIndex = start;
    while (t + 2 <= last) : (t += 1) {
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
        if (!std.mem.eql(u8, tree.tokenSlice(t), x_name)) continue;
        // `<X> = ...` — rebinding, stop.
        if (tags[t + 1] == .equal) return null;
        // `<X>.* = ...` — deref-write.  `.*` is a SINGLE token
        // (period_asterisk).
        if (tags[t + 1] == .period_asterisk) {
            if (t + 2 <= last and tags[t + 2] == .equal) return t;
            continue;
        }
        if (tags[t + 1] != .period) continue;
        if (t + 2 > last) continue;
        // `<X>.<field> = ...`.
        if (tags[t + 2] != .identifier) continue;
        if (t + 3 > last) continue;
        if (tags[t + 3] == .equal) return t;
        // `<X>.<method>(...)` — if method is `destroy`/`free` of X
        // again, stop (next scope or rare double-free shape covered
        // by other rules).  Otherwise just skip.
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
    write_tok: Ast.TokenIndex,
    x_name: []const u8,
    method: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "write through `{s}` after `<alloc>.{s}({s})` — the write hits freed memory.  The TigerStyle invariant is overwrite-THEN-free: `{s}.* = undefined; <alloc>.{s}({s});` (not the other order)",
        .{ x_name, method, x_name, x_name, method, x_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "self-undefined-after-destroy",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, write_tok),
        .end = Pos.fromTokenEnd(tree, write_tok),
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

test "self-undefined-after-destroy: TigerBeetle inspect.zig pattern fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Inspector = struct {
        \\    allocator: std.mem.Allocator,
        \\    pub fn deinit(inspector: *Inspector) void {
        \\        inspector.allocator.destroy(inspector);
        \\        inspector.* = undefined;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("self-undefined-after-destroy", problems.items[0].rule_id);
}

test "self-undefined-after-destroy: correct order (undefined THEN destroy) doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Inspector = struct {
        \\    allocator: std.mem.Allocator,
        \\    pub fn deinit(inspector: *Inspector) void {
        \\        inspector.* = undefined;
        \\        inspector.allocator.destroy(inspector);
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "self-undefined-after-destroy: field write after destroy fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const T = struct {
        \\    flag: bool = false,
        \\    pub fn release(self: *T, alloc: std.mem.Allocator) void {
        \\        alloc.destroy(self);
        \\        self.flag = true;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "self-undefined-after-destroy: reassignment of X stops the scan" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const T = struct {
        \\    pub fn rebind(self: *T, alloc: std.mem.Allocator) !void {
        \\        alloc.destroy(self);
        \\        // self is now stale, but the next line rebinds it.
        \\        var self_new = try alloc.create(T);
        \\        _ = self_new;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "self-undefined-after-destroy: destroy inside defer is skipped" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const T = struct {
        \\    pub fn work(self: *T, alloc: std.mem.Allocator) void {
        \\        defer alloc.destroy(self);
        \\        self.* = .{};
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    // The destroy is deferred (runs at scope exit, AFTER the
    // assignment).  Not a UAF, must not fire.
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
