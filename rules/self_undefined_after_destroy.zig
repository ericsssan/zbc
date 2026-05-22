//! `<alloc>.destroy(<X>);` immediately followed by a write through
//! `<X>` — `<X>.* = ...;` or `<X>.<field> = ...;`.  Inverted
//! TigerStyle invariant: correct order is overwrite-THEN-free.
//!
//! Real-world: tigerbeetle/tigerbeetle#2687.

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("../lexer.zig");
const scope = @import("../scope.zig");
const problem = @import("../problem.zig");
const testing = @import("../testing.zig");
const config_mod = @import("../config.zig");

const TokenIndex = lexer.TokenIndex;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(problem.Problem),
) !void {
    if (!config_mod.isEnabled(config, .self_undefined_after_destroy)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = lexer.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        try checkBody(gpa, tree, fn_entry.body, problems);
    }
}

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(problem.Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var walk = scope.BodyWalk.init(tags, first, last);
    while (walk.t + 4 <= last) : (walk.t += 1) {
        if (walk.atNestedFn()) {
            walk.skipNestedFn();
            continue;
        }
        if (walk.atDeferKeyword()) {
            walk.skipDeferStmt();
            continue;
        }
        // Pattern: `.destroy(<X>)` or `.free(<X>)` preceded by `.`.
        const t = walk.t;
        if (tags[t] != .identifier) continue;
        if (t == 0 or tags[t - 1] != .period) continue;
        const method = tree.tokenSlice(t);
        if (!std.mem.eql(u8, method, "destroy") and !std.mem.eql(u8, method, "free")) continue;
        if (tags[t + 1] != .l_paren) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .r_paren) continue;
        const x_name = tree.tokenSlice(t + 2);
        // Defensive: skip `<name>.destroy(<name>)` (nonsense).
        if (t >= 2 and tags[t - 2] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t - 2), x_name)) continue;
        const sc = lexer.findStmtSemicolon(tags, t + 4, last) orelse continue;
        const write_tok = findWriteThroughX(tree, sc + 1, last, x_name) orelse {
            walk.t = sc;
            continue;
        };
        try report(gpa, problems, tree, write_tok, x_name, method);
        walk.t = sc;
    }
}

/// Scan `[start, last]` for the first write through `<X>` —
/// `<X>.* = ...` or `<X>.<field> = ...`.  Bounded by enclosing
/// scope; skips nested blocks / defer / errdefer; stops at
/// reassignment of `<X>`.
fn findWriteThroughX(
    tree: *const Ast,
    start: TokenIndex,
    last: TokenIndex,
    x_name: []const u8,
) ?TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var t: TokenIndex = start;
    while (t + 2 <= last) : (t += 1) {
        if (tags[t] == .l_brace) {
            t = lexer.matchBrace(tags, t, last) orelse return null;
            continue;
        }
        if (tags[t] == .r_brace) return null;
        if (tags[t] == .keyword_defer or tags[t] == .keyword_errdefer) {
            t = lexer.skipDeferStmt(tags, t, last) orelse return null;
            continue;
        }
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), x_name)) continue;
        // `<X> = ...` — rebinding, stop.
        if (tags[t + 1] == .equal) return null;
        // `<X>.* = ...` — deref-write.
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
    }
    return null;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(problem.Problem),
    tree: *const Ast,
    write_tok: TokenIndex,
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
        .start = problem.Pos.fromTokenStart(tree, write_tok),
        .end = problem.Pos.fromTokenEnd(tree, write_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

const R = "self-undefined-after-destroy";

test "TigerBeetle inspect.zig pattern fires" {
    try testing.expectFires(check, R,
        \\const std = @import("std");
        \\const Inspector = struct {
        \\    allocator: std.mem.Allocator,
        \\    pub fn deinit(inspector: *Inspector) void {
        \\        inspector.allocator.destroy(inspector);
        \\        inspector.* = undefined;
        \\    }
        \\};
    );
}

test "correct order (undefined THEN destroy) doesn't fire" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\const Inspector = struct {
        \\    allocator: std.mem.Allocator,
        \\    pub fn deinit(inspector: *Inspector) void {
        \\        inspector.* = undefined;
        \\        inspector.allocator.destroy(inspector);
        \\    }
        \\};
    );
}

test "field write after destroy fires" {
    try testing.expectFires(check, R,
        \\const std = @import("std");
        \\const T = struct {
        \\    flag: bool = false,
        \\    pub fn release(self: *T, alloc: std.mem.Allocator) void {
        \\        alloc.destroy(self);
        \\        self.flag = true;
        \\    }
        \\};
    );
}

test "reassignment of X stops the scan" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\const T = struct {
        \\    pub fn rebind(self: *T, alloc: std.mem.Allocator) !void {
        \\        alloc.destroy(self);
        \\        var self_new = try alloc.create(T);
        \\        _ = self_new;
        \\    }
        \\};
    );
}

test "destroy inside defer is skipped" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\const T = struct {
        \\    pub fn work(self: *T, alloc: std.mem.Allocator) void {
        \\        defer alloc.destroy(self);
        \\        self.* = .{};
        \\    }
        \\};
    );
}
