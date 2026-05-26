//! Deinit-order-violates-construction-dep detector — within a
//! single fn body, two struct instances `A` and `B` are
//! constructed via `<A> = <T>.init(&<B>, ...)` (so `A` depends
//! on `B`).  Later, the same fn calls `<B>.deinit(...)` BEFORE
//! `<A>.deinit(...)`.  `A`'s deinit may dereference its
//! borrowed `B` pointer — but `B` is already torn down.
//!
//! Real-world: tigerbeetle/tigerbeetle#3732 (`manifest_log_fuzz.zig`:
//! `env.grid_verify.deinit()` ran before `env.manifest_log_verify.deinit()`,
//! and ManifestLog holds a pointer to Grid).
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Collect "dep" edges: `<A> = <T>.init(&<B>, ...)` or
//!      `<A>.init(&<B>, ...)` — meaning A depends on B.  Both
//!      LHS receiver chains (`a`, `env.grid_verify`) are
//!      flattened to the last identifier for comparison.
//!   3. Walk the body for sequences of `<X>.deinit(...)` calls.
//!      For each pair (B-deinit, then A-deinit) in source order
//!      where (B → A) is a dep edge, fire on the second deinit.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const lexer = @import("../lexer.zig");
const testing = @import("../testing.zig");
const skipNestedFn = lexer.skipNestedFn;
const returnsType = lexer.returnsType;
const bodyOf = lexer.bodyOf;

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .deinit_order_violates_construction_dep)) return;
    _ = cache;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        if (returnsType(tree, node)) continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, body, problems);
    }
}

const Dep = struct {
    a_name: []const u8, // last identifier of the LHS receiver chain
    b_name: []const u8, // last identifier of the &b argument
};

const Deinit = struct {
    recv_name: []const u8, // last identifier of `<chain>.deinit(`
    tok: Ast.TokenIndex,
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

    var deps: std.ArrayListUnmanaged(Dep) = .empty;
    defer deps.deinit(gpa);

    // Collect dep edges: `<A> = ...<T>.init(&<B>, ...)` or
    // `<A>.init(&<B>, ...)`.
    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        // Look for `init(` followed by `&<ident>` as first arg.
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "init")) continue;
        if (t == 0 or tags[t - 1] != .period) continue;
        if (tags[t + 1] != .l_paren) continue;
        if (t + 3 > last) continue;
        if (tags[t + 2] != .ampersand) continue;
        if (tags[t + 3] != .identifier) continue;
        const b_name = lastIdentSegment(tree, tags, t + 3, last);
        // Find LHS — walk back to the `=` or to the start of the
        // assignee chain.  Pattern A: `<lhs-chain> = <T>.init(...)`.
        // Pattern B: `<lhs-chain>.init(...)` — first method-call
        // form.
        const a_name = findInitAssignee(tree, tags, first, t) orelse continue;
        try deps.append(gpa, .{ .a_name = a_name, .b_name = b_name });
    }
    if (deps.items.len == 0) return;

    // Collect deinit calls in source order: `<chain>.deinit(`.
    var deinits: std.ArrayListUnmanaged(Deinit) = .empty;
    defer deinits.deinit(gpa);
    t = first;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "deinit")) continue;
        if (t == 0 or tags[t - 1] != .period) continue;
        if (tags[t + 1] != .l_paren) continue;
        const recv = lastIdentSegmentBack(tree, tags, t - 1);
        try deinits.append(gpa, .{ .recv_name = recv, .tok = t });
    }
    if (deinits.items.len < 2) return;

    // For each ordered pair (deinit[i], deinit[j]) with i<j,
    // check if deps contains (a=deinit[j].recv, b=deinit[i].recv).
    for (deinits.items, 0..) |di, i| {
        for (deinits.items[i + 1 ..]) |dj| {
            for (deps.items) |d| {
                if (std.mem.eql(u8, d.a_name, dj.recv_name) and
                    std.mem.eql(u8, d.b_name, di.recv_name))
                {
                    try report(gpa, problems, tree, dj.tok, d.a_name, d.b_name);
                    break;
                }
            }
        }
    }
}

/// Walk forward through the receiver chain starting at `start`
/// and return the LAST identifier segment.
fn lastIdentSegment(tree: *const Ast, tags: []const std.zig.Token.Tag, start: Ast.TokenIndex, last: Ast.TokenIndex) []const u8 {
    var t: Ast.TokenIndex = start;
    var last_ident = start;
    while (t <= last) : (t += 1) {
        if (tags[t] == .identifier) last_ident = t;
        if (tags[t] == .period and t + 1 <= last and tags[t + 1] == .identifier) continue;
        if (t > start and tags[t] != .identifier and tags[t] != .period) break;
    }
    return tree.tokenSlice(last_ident);
}

/// Walk backward from `period_tok` (the `.` before `init` /
/// `deinit`) through the receiver chain and return the LAST
/// identifier segment (the closest one to the method).
fn lastIdentSegmentBack(tree: *const Ast, tags: []const std.zig.Token.Tag, period_tok: Ast.TokenIndex) []const u8 {
    if (period_tok == 0) return &.{};
    if (tags[period_tok - 1] != .identifier) return &.{};
    return tree.tokenSlice(period_tok - 1);
}

/// Find the assignee identifier name for an init call.  Walks
/// back from the `init` token to find either `<lhs> = <T>.init(`
/// or `<lhs-chain>.init(` shapes.  Returns the LAST identifier
/// of the LHS (e.g. `grid_verify` for `env.grid_verify = ...`).
fn findInitAssignee(tree: *const Ast, tags: []const std.zig.Token.Tag, first: Ast.TokenIndex, init_tok: Ast.TokenIndex) ?[]const u8 {
    // Walk back across the receiver chain that ends at `.init`.
    var t: Ast.TokenIndex = init_tok;
    if (t < 2) return null;
    t -= 2; // skip `.` and method
    // Walk back across the type-name chain: `<T1>.<T2>...<Tn>`.
    while (t >= 2 and tags[t] == .identifier and tags[t - 1] == .period and tags[t - 2] == .identifier) {
        t -= 2;
    }
    if (tags[t] != .identifier) return null;
    // At this point `t` is the leftmost identifier before the
    // type/method chain.  Two cases:
    //   A) `<a> = <T>.init(...)` — the token before `t` is `=`.
    //      Walk back over `=` and over the LHS receiver chain.
    //   B) `<chain>.init(...)` — `t` IS the assignee's leftmost
    //      receiver (no `=` involved).
    if (t == 0 or tags[t - 1] != .equal) {
        // Case B: assignee is the chain ending here.  Return the
        // chain's LAST identifier (the rightmost).
        return tree.tokenSlice(t);
    }
    // Case A: walk back over `=` then back through `<lhs-chain>`.
    var u: Ast.TokenIndex = t - 2; // skip space + `=`... well, no space tokens; just `=`.
    if (u < first) return null;
    if (tags[u] != .identifier) return null;
    const last_ident = u;
    // (Walk back to find the leftmost segment, even though we
    // return the rightmost — purely to validate the chain shape.)
    while (u >= 2 and tags[u - 1] == .period and tags[u - 2] == .identifier) {
        u -= 2;
    }
    return tree.tokenSlice(last_ident);
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    deinit_tok: Ast.TokenIndex,
    a_name: []const u8,
    b_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}.deinit(...)` runs AFTER `{s}.deinit(...)` — but `{s}` was constructed via `.init(&{s}, ...)`, so `{s}` borrows from `{s}` and its deinit may dereference a torn-down value.  Reverse the order (LIFO)",
        .{ a_name, b_name, a_name, b_name, a_name, b_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "deinit-order-violates-construction-dep",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, deinit_tok),
        .end = Pos.fromTokenEnd(tree, deinit_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    return testing.runRule(gpa, check, src);
}

const freeProblems = testing.freeProblems;

test "deinit-order-violates-construction-dep: LIFO violation fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Grid = struct {
        \\    pub fn init() Grid { return .{}; }
        \\    pub fn deinit(_: *Grid) void {}
        \\};
        \\const ManifestLog = struct {
        \\    pub fn init(_: *Grid) ManifestLog { return .{}; }
        \\    pub fn deinit(_: *ManifestLog) void {}
        \\};
        \\pub fn run() void {
        \\    var grid_verify = Grid.init();
        \\    var manifest_log_verify = ManifestLog.init(&grid_verify);
        \\    grid_verify.deinit();
        \\    manifest_log_verify.deinit();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
    try std.testing.expectEqualStrings("deinit-order-violates-construction-dep", problems.items[0].rule_id);
}

test "deinit-order-violates-construction-dep: correct LIFO order doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Grid = struct {
        \\    pub fn init() Grid { return .{}; }
        \\    pub fn deinit(_: *Grid) void {}
        \\};
        \\const ManifestLog = struct {
        \\    pub fn init(_: *Grid) ManifestLog { return .{}; }
        \\    pub fn deinit(_: *ManifestLog) void {}
        \\};
        \\pub fn run() void {
        \\    var grid_verify = Grid.init();
        \\    var manifest_log_verify = ManifestLog.init(&grid_verify);
        \\    manifest_log_verify.deinit();
        \\    grid_verify.deinit();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
