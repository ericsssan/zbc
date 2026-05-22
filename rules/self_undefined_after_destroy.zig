//! `<alloc>.destroy(<X>);` immediately followed by a write through
//! `<X>` — `<X>.* = ...;` or `<X>.<field> = ...;`.  Inverted
//! TigerStyle invariant: correct order is overwrite-THEN-free.
//!
//! Real-world: tigerbeetle/tigerbeetle#2687.

const std = @import("std");
const Ast = std.zig.Ast;

const sdk = @import("../analysis.zig");
const config_mod = @import("../config.zig");

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(sdk.Problem),
) !void {
    if (!config_mod.isEnabled(config, .self_undefined_after_destroy)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = sdk.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        try checkBody(gpa, tree, fn_entry.body, problems);
    }
}

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(sdk.Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var walk = sdk.BodyWalk.init(tags, first, last);
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
        const sc = sdk.findStmtSemicolon(tags, t + 4, last) orelse continue;
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
    start: sdk.TokenIndex,
    last: sdk.TokenIndex,
    x_name: []const u8,
) ?sdk.TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var t: sdk.TokenIndex = start;
    while (t + 2 <= last) : (t += 1) {
        if (tags[t] == .l_brace) {
            t = sdk.matchBrace(tags, t, last) orelse return null;
            continue;
        }
        if (tags[t] == .r_brace) return null;
        if (tags[t] == .keyword_defer or tags[t] == .keyword_errdefer) {
            t = sdk.skipDeferStmt(tags, t, last) orelse return null;
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
    problems: *std.ArrayListUnmanaged(sdk.Problem),
    tree: *const Ast,
    write_tok: sdk.TokenIndex,
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
        .start = sdk.Pos.fromTokenStart(tree, write_tok),
        .end = sdk.Pos.fromTokenEnd(tree, write_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(sdk.Problem) {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);
    var problems: std.ArrayListUnmanaged(sdk.Problem) = .empty;
    try check(gpa, &tree, &config_mod.Default, &problems);
    return problems;
}

fn freeProblems(gpa: std.mem.Allocator, p: *std.ArrayListUnmanaged(sdk.Problem)) void {
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
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
