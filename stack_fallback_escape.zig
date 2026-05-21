//! ghostty-org/ghostty#9885 class — `std.heap.stackFallback(N,
//! <alloc>)` returns an allocator whose small allocations land in
//! the *caller's* stack frame.  When a value-yielding method on a
//! container built over `<SF>.get()` (e.g. `toOwnedSlice`) is
//! returned without first being copied through the real allocator,
//! the slice points into the dead stack buffer once the fn frame
//! exits — UAF whenever the allocation stays under N.
//!
//! Detection per fn (purely syntactic):
//!
//!   1. Find `var <SF> = …stackFallback(<N>, <alloc>);` bindings.
//!      Record `<SF>` ident.  (Inner-alloc name not needed for v1.)
//!   2. Track SF-tainted locals: any `var <X> = <expr>` whose RHS
//!      contains `<SF>.get()` (the allocator the fallback hands
//!      out).  This captures `T.init(<SF>.get())`,
//!      `ArrayList(...).init(<SF>.get())`, etc.
//!   3. Walk the rest of the body for `return <expr>` where
//!      `<expr>` contains a `.toOwnedSlice` / `.toOwnedSliceSentinel`
//!      / `.allocPrint` / etc. call on an SF-tainted local —
//!      directly or via a single intermediate binding.
//!   4. Fire at the `return` site.  v1 doesn't try to detect
//!      sanitization through `<alloc>.dupe*` etc.; the canonical
//!      bug shape returns the toOwnedSlice result directly.

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
    if (!config_mod.isEnabled(config, .stack_fallback_escape)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
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

    // Phase 1: find stackFallback bindings.  Record SF ident names.
    var sf_names: std.ArrayListUnmanaged([]const u8) = .empty;
    defer sf_names.deinit(gpa);
    var t: Ast.TokenIndex = first;
    while (t + 4 < last) : (t += 1) {
        if (tags[t] != .keyword_var and tags[t] != .keyword_const) continue;
        if (tags[t + 1] != .identifier) continue;
        // Find the `=` that ends this var/const's LHS, then look
        // for `stackFallback(` somewhere in the RHS token range up
        // to the statement-end semicolon.
        const eq = findEqualAtStmt(tags, t + 2, last) orelse continue;
        const sc = findStmtSemicolon(tags, eq + 1, last) orelse continue;
        if (!tokenRangeContainsCall(tree, eq + 1, sc, "stackFallback")) continue;
        try sf_names.append(gpa, tree.tokenSlice(t + 1));
    }
    if (sf_names.items.len == 0) return;

    // Phase 2: find SF-tainted locals.  Any `var/const <X> = <RHS>`
    // where the RHS token range contains `<SF>.get()` (call site)
    // makes X tainted.  Also propagate one step: if `<X>` is
    // tainted and `var <Y> = <RHS-mentioning-X>`, Y is tainted.
    var tainted: std.StringHashMapUnmanaged(void) = .empty;
    defer tainted.deinit(gpa);
    t = first;
    while (t + 4 < last) : (t += 1) {
        if (tags[t] != .keyword_var and tags[t] != .keyword_const) continue;
        if (tags[t + 1] != .identifier) continue;
        const eq = findEqualAtStmt(tags, t + 2, last) orelse continue;
        const sc = findStmtSemicolon(tags, eq + 1, last) orelse continue;
        const name = tree.tokenSlice(t + 1);
        if (std.mem.eql(u8, name, "_")) continue;
        var is_tainted = false;
        // Direct taint: RHS contains `<SF>.get`.
        for (sf_names.items) |sf| {
            if (rhsHasSfGet(tree, eq + 1, sc, sf)) {
                is_tainted = true;
                break;
            }
        }
        // Transitive taint: RHS mentions an existing tainted ident.
        if (!is_tainted) {
            var u: Ast.TokenIndex = eq + 1;
            while (u < sc) : (u += 1) {
                if (tags[u] != .identifier) continue;
                const id = tree.tokenSlice(u);
                if (tainted.contains(id)) {
                    is_tainted = true;
                    break;
                }
            }
        }
        if (is_tainted) try tainted.put(gpa, name, {});
    }

    // Phase 3: scan returns.  Fire if a return's value expression
    // contains `<tainted>.toOwnedSlice(` / `.toOwnedSliceSentinel(`
    // / `.allocPrint(` / `.allocPrintZ(` — these methods produce a
    // slice into the tainted allocator's backing storage.  Skip
    // when the return value also contains a `.dupe*(...)` /
    // `.alloc*(...)` call — those wrap-and-copy the tainted slice
    // through the inner allocator, which is the canonical fix
    // (e.g. `try alloc.dupeZ(u8, try cmd.toOwnedSlice())`).
    t = first;
    while (t < last) : (t += 1) {
        if (tags[t] != .keyword_return) continue;
        const sc = findStmtSemicolon(tags, t + 1, last) orelse continue;
        if (returnHasSanitizingCopy(tree, t + 1, sc)) continue;
        if (findTaintedToOwned(tree, t + 1, sc, &tainted)) |hit| {
            try report(gpa, problems, tree, t, hit.local, hit.method);
        }
    }
}

/// True iff the return value's token range contains a
/// `.dupe(` / `.dupeZ(` / `.alloc(` / `.allocSentinel(` /
/// `.create(` etc. call — the canonical "copy through a real
/// allocator" sanitization that fixes the bug.
fn returnHasSanitizingCopy(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 2 < end) : (t += 1) {
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .l_paren) continue;
        const m = tree.tokenSlice(t + 1);
        if (std.mem.eql(u8, m, "dupe") or
            std.mem.eql(u8, m, "dupeZ") or
            std.mem.eql(u8, m, "alloc") or
            std.mem.eql(u8, m, "allocSentinel") or
            std.mem.eql(u8, m, "create")) return true;
    }
    return false;
}

const Hit = struct {
    local: []const u8,
    method: []const u8,
};

/// Find any `<tainted_ident>.<sink_method>(` occurrence in the
/// range `[start, end)` and return the matched local + method.
fn findTaintedToOwned(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    tainted: *const std.StringHashMapUnmanaged(void),
) ?Hit {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 3 < end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        const local = tree.tokenSlice(t);
        if (!tainted.contains(local)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .l_paren) continue;
        const method = tree.tokenSlice(t + 2);
        if (!isSinkMethodName(method)) continue;
        return .{ .local = local, .method = method };
    }
    return null;
}

fn isSinkMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "toOwnedSlice") or
        std.mem.eql(u8, name, "toOwnedSliceSentinel") or
        std.mem.eql(u8, name, "allocPrint") or
        std.mem.eql(u8, name, "allocPrintZ") or
        std.mem.eql(u8, name, "allocPrintSentinel") or
        std.mem.eql(u8, name, "concat") or
        std.mem.eql(u8, name, "join") or
        std.mem.eql(u8, name, "joinZ");
}

/// True iff `[start, end)` contains `<sf>.get(` at any nesting depth.
fn rhsHasSfGet(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex, sf: []const u8) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 3 < end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), sf)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), "get")) continue;
        if (tags[t + 3] != .l_paren) continue;
        return true;
    }
    return false;
}

/// True iff `[start, end)` contains a `<name>(` call at any depth.
fn tokenRangeContainsCall(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex, name: []const u8) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 1 < end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), name)) continue;
        if (tags[t + 1] != .l_paren) continue;
        return true;
    }
    return false;
}

/// Walk forward from `start` to find the first `=` at statement depth
/// (paren/brace/bracket all zero).  Skips past optional type annotation.
fn findEqualAtStmt(tags: []const std.zig.Token.Tag, start: Ast.TokenIndex, last: Ast.TokenIndex) ?Ast.TokenIndex {
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
            .equal => if (paren == 0 and brace == 0 and bracket == 0) return t,
            .semicolon => if (paren == 0 and brace == 0 and bracket == 0) return null,
            else => {},
        }
    }
    return null;
}

fn findStmtSemicolon(tags: []const std.zig.Token.Tag, start: Ast.TokenIndex, last: Ast.TokenIndex) ?Ast.TokenIndex {
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

fn bodyOf(tree: *const Ast, node: Ast.Node.Index) ?Ast.Node.Index {
    if (tree.nodeTag(node) != .fn_decl) return null;
    return tree.nodeData(node).node_and_node[1];
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    return_tok: Ast.TokenIndex,
    local: []const u8,
    method: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}.{s}()` returns a slice into the `stackFallback(...)` buffer in the caller's stack frame — escaping it via `return` dangles the pointer once this fn exits.  Bind the result locally and `try <inner_alloc>.dupe*(...)` it before returning",
        .{ local, method },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "stack-fallback-escape",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, return_tok),
        .end = Pos.fromTokenEnd(tree, return_tok),
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

test "stack-fallback-escape: `return cmd.toOwnedSlice()` from SF-tainted local fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Builder = struct {
        \\    pub fn init(_: std.mem.Allocator) Builder { return .{}; }
        \\    pub fn toOwnedSlice(_: *Builder) ![]u8 { return &.{}; }
        \\};
        \\const Shell = struct { shell: []u8 };
        \\pub fn setup(alloc: std.mem.Allocator) !Shell {
        \\    var sf = std.heap.stackFallback(4096, alloc);
        \\    var cmd = Builder.init(sf.get());
        \\    return .{ .shell = try cmd.toOwnedSlice() };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("stack-fallback-escape", problems.items[0].rule_id);
}

test "stack-fallback-escape: dupe through inner allocator is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Builder = struct {
        \\    pub fn init(_: std.mem.Allocator) Builder { return .{}; }
        \\    pub fn toOwnedSlice(_: *Builder) ![]u8 { return &.{}; }
        \\};
        \\const Shell = struct { shell: []u8 };
        \\pub fn setup(alloc: std.mem.Allocator) !Shell {
        \\    var sf = std.heap.stackFallback(4096, alloc);
        \\    var cmd = Builder.init(sf.get());
        \\    const tmp = try cmd.toOwnedSlice();
        \\    return .{ .shell = try alloc.dupe(u8, tmp) };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // The toOwnedSlice result is bound to `tmp` and then `tmp` is
    // copied through `alloc.dupe`.  My detector currently only
    // flags DIRECT `<tainted>.toOwnedSlice(...)` in a return; this
    // case has the toOwnedSlice in a binding, then the return uses
    // `alloc.dupe(u8, tmp)` (no tainted-local method-call in
    // return).  So no fire.
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "stack-fallback-escape: no stackFallback present is silent" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Builder = struct {
        \\    pub fn init(_: std.mem.Allocator) Builder { return .{}; }
        \\    pub fn toOwnedSlice(_: *Builder) ![]u8 { return &.{}; }
        \\};
        \\pub fn setup(alloc: std.mem.Allocator) ![]u8 {
        \\    var cmd = Builder.init(alloc);
        \\    return try cmd.toOwnedSlice();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "stack-fallback-escape: SF-tainted local consumed only locally is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Builder = struct {
        \\    pub fn init(_: std.mem.Allocator) Builder { return .{}; }
        \\    pub fn toOwnedSlice(_: *Builder) ![]u8 { return &.{}; }
        \\    pub fn deinit(_: *Builder) void {}
        \\};
        \\pub fn doStuff(alloc: std.mem.Allocator, _: usize) !void {
        \\    var sf = std.heap.stackFallback(4096, alloc);
        \\    var cmd = Builder.init(sf.get());
        \\    defer cmd.deinit();
        \\    const slice = try cmd.toOwnedSlice();
        \\    _ = slice;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    // Tainted slice is bound locally and discarded — no return
    // mentions it, so no escape.
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "stack-fallback-escape: transitive taint via inner var fires when returned" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Inner = struct {
        \\    pub fn init(_: std.mem.Allocator) Inner { return .{}; }
        \\};
        \\const Outer = struct {
        \\    pub fn init(_: Inner) Outer { return .{}; }
        \\    pub fn toOwnedSlice(_: *Outer) ![]u8 { return &.{}; }
        \\};
        \\pub fn build(alloc: std.mem.Allocator) ![]u8 {
        \\    var sf = std.heap.stackFallback(4096, alloc);
        \\    const inner = Inner.init(sf.get());
        \\    var outer = Outer.init(inner);
        \\    return try outer.toOwnedSlice();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}
