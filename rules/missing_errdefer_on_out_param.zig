//! Multi-step in-place struct-builder pattern that acquires a
//! resource via `try <out>.<field>.<acquire>(...);` (where `<out>`
//! is a local that will be returned, like `result` or `out`), but
//! has a later `try` with no `errdefer` registered to release the
//! acquired field on error.
//!
//! Real-world: ghostty-org/ghostty#10401 — `SharedGrid.init` did
//!
//!   try result.codepoints.ensureTotalCapacity(alloc, 128);
//!   try result.glyphs.ensureTotalCapacity(alloc, 128);
//!   try result.reloadMetrics();           // ← fallible; codepoints
//!                                          //   and glyphs leak on err
//!   return result;
//!
//! The fix interleaves errdefers:
//!
//!   try result.codepoints.ensureTotalCapacity(alloc, 128);
//!   errdefer result.codepoints.deinit(alloc);
//!   try result.glyphs.ensureTotalCapacity(alloc, 128);
//!   errdefer result.glyphs.deinit(alloc);
//!   try result.reloadMetrics();
//!
//! Complements existing `missing-errdefer-between-tries` (binding-
//! and-leak `const X = try Type.method()` shape) — this rule covers
//! the in-place struct-builder variant where the acquired resource
//! lives in `<out>.<field>` rather than a freshly-bound local.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Skip fns with no `try` (proxy for "doesn't return !T").
//!   3. Walk for `try <out>.<field>.<acquire>(...)` where `<out>`
//!      is one of {`result`, `out`, `r`} and `<acquire>` is in the
//!      allowlist below.
//!   4. From the statement end, scan for the next `try` in the
//!      same fn body.  If no errdefer referencing `<out>.<field>`
//!      appears between, fire.
//!
//! Acquire-method allowlist (calls that allocate or take ownership):
//!   ensureTotalCapacity / ensureUnusedCapacity / initCapacity /
//!   init / append / appendSlice / put / clone / dupe / alloc /
//!   create.

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
    if (!config_mod.isEnabled(config, .missing_errdefer_on_out_param)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        if (returnsType(tree, node)) continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, body, problems);
    }
}

const Acquire = struct {
    out_name: []const u8,
    field_name: []const u8,
    /// Token of the acquire method (anchor for diagnostic).
    method_tok: Ast.TokenIndex,
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

    // Cheap pre-pass: fn must contain `try` somewhere.
    if (!hasTokenInRange(tags, first, last, .keyword_try)) return;

    var acquires: std.ArrayListUnmanaged(Acquire) = .empty;
    defer acquires.deinit(gpa);

    var t: Ast.TokenIndex = first;
    while (t + 6 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_try) continue;
        // Pattern: `try <out>.<field>.<method>(`
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .period) continue;
        if (tags[t + 3] != .identifier) continue;
        if (tags[t + 4] != .period) continue;
        if (tags[t + 5] != .identifier) continue;
        if (tags[t + 6] != .l_paren) continue;
        const out = tree.tokenSlice(t + 1);
        if (!isCanonicalOutName(out)) continue;
        // Out-param must be declared `var <out>: T = .{ ... };` —
        // skip if it's bound via `const <out> = ...` (e.g. a
        // hashmap `getOrPut` entry, not a fresh struct being built).
        if (!isVarBinding(tree, first, last, out)) continue;
        const method = tree.tokenSlice(t + 5);
        if (!isAcquireMethodName(method)) continue;
        const field = tree.tokenSlice(t + 3);
        const sc = findStmtSemicolon(tags, t + 6, last) orelse continue;
        try acquires.append(gpa, .{
            .out_name = out,
            .field_name = field,
            .method_tok = t + 5,
            .end_token = sc,
        });
        t = sc;
    }

    // A whole-fn errdefer (`errdefer <out>.deinit();` at fn-body
    // top) protects every acquire — when any later try fails, the
    // errdefer fires and cleans up the partially-built struct.
    // Detect it ONCE for the whole fn body and use as a cheap
    // suppressor.
    const has_whole_fn_errdefer = bodyHasErrdeferOn(tree, first, last);

    for (acquires.items) |a| {
        if (has_whole_fn_errdefer) continue;
        // After this acquire's `;`, scan for the next `try`.  If an
        // errdefer referencing `<out>` appears first, the resource
        // is protected.
        var u: Ast.TokenIndex = a.end_token + 1;
        var has_errdefer = false;
        var has_next_try = false;
        while (u <= last) : (u += 1) {
            if (tags[u] == .keyword_errdefer) {
                if (errdeferReferences(tree, u, last, a.out_name, a.field_name)) {
                    has_errdefer = true;
                    break;
                }
            }
            if (tags[u] == .keyword_try) {
                has_next_try = true;
                break;
            }
        }
        if (has_next_try and !has_errdefer) {
            try report(gpa, problems, tree, a);
        }
    }
}

/// True iff `[first, last]` contains any `errdefer` mentioning one
/// of the canonical out-names — `errdefer result.deinit()` /
/// `errdefer out.x.deinit()` / etc.  Used to suppress the rule's
/// entire output for a fn that has a whole-struct cleanup
/// registered (the canonical Zig idiom).
fn bodyHasErrdeferOn(
    tree: *const Ast,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t + 2 <= last) : (t += 1) {
        if (tags[t] != .keyword_errdefer) continue;
        // Loose: scan the next few tokens for one of the canonical
        // out-names.
        var u: Ast.TokenIndex = t + 1;
        const limit: Ast.TokenIndex = if (t + 16 > last) last else t + 16;
        while (u <= limit) : (u += 1) {
            if (tags[u] != .identifier) continue;
            const n = tree.tokenSlice(u);
            if (isCanonicalOutName(n)) return true;
        }
    }
    return false;
}

/// True iff `<out>` is declared as `var <out>` (not `const`) in
/// the fn body — the canonical out-param-being-built shape.
fn isVarBinding(
    tree: *const Ast,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
    out: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t + 1 <= last) : (t += 1) {
        if (tags[t] != .keyword_var and tags[t] != .keyword_const) continue;
        if (tags[t + 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 1), out)) continue;
        return tags[t] == .keyword_var;
    }
    // No declaration found — could be a parameter; treat as not-an-
    // out-param.
    return false;
}

fn isCanonicalOutName(name: []const u8) bool {
    return std.mem.eql(u8, name, "result") or
        std.mem.eql(u8, name, "out") or
        std.mem.eql(u8, name, "r");
}

fn isAcquireMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "ensureTotalCapacity") or
        std.mem.eql(u8, name, "ensureUnusedCapacity") or
        std.mem.eql(u8, name, "initCapacity") or
        std.mem.eql(u8, name, "init") or
        std.mem.eql(u8, name, "append") or
        std.mem.eql(u8, name, "appendSlice") or
        std.mem.eql(u8, name, "put") or
        std.mem.eql(u8, name, "clone") or
        std.mem.eql(u8, name, "dupe") or
        std.mem.eql(u8, name, "alloc") or
        std.mem.eql(u8, name, "create");
}

/// True iff the errdefer at `kw` mentions `<out>` in its body
/// (inline or block form).  Loose match — any appearance of `<out>`
/// as an identifier counts as protection.  This intentionally
/// accepts whole-struct errdefers (`errdefer result.deinit()`) as
/// well as field-specific ones (`errdefer result.codepoints.deinit(alloc)`),
/// because a whole-struct deinit is the canonical Zig idiom and
/// will clean up the partially-populated field.
fn errdeferReferences(
    tree: *const Ast,
    kw: Ast.TokenIndex,
    last: Ast.TokenIndex,
    out: []const u8,
    field: []const u8,
) bool {
    _ = field;
    const tags = tree.tokens.items(.tag);
    if (kw + 1 > last) return false;
    var scan_start: Ast.TokenIndex = kw + 1;
    if (tags[scan_start] == .pipe) {
        var p: Ast.TokenIndex = scan_start + 1;
        while (p <= last and tags[p] != .pipe) : (p += 1) {}
        if (p > last) return false;
        scan_start = p + 1;
    }
    if (scan_start > last) return false;
    const range_end = if (tags[scan_start] == .l_brace)
        (matchBrace(tags, scan_start, last) orelse last)
    else
        (findStmtSemicolon(tags, scan_start, last) orelse last);
    var t: Ast.TokenIndex = scan_start;
    while (t <= range_end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (std.mem.eql(u8, tree.tokenSlice(t), out)) return true;
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
    a: Acquire,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`try {s}.{s}.<acquire>(...)` populated `{s}.{s}`, but a later `try` in this fn has no `errdefer {s}.{s}.deinit(...)` between them — `{s}.{s}` leaks every time the next `try` propagates an error",
        .{ a.out_name, a.field_name, a.out_name, a.field_name, a.out_name, a.field_name, a.out_name, a.field_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "missing-errdefer-on-out-param",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, a.method_tok),
        .end = Pos.fromTokenEnd(tree, a.method_tok),
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

test "missing-errdefer-on-out-param: SharedGrid.init pattern fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Self = struct {
        \\    codepoints: std.AutoHashMap(u32, u32),
        \\    glyphs: std.AutoHashMap(u32, u32),
        \\    pub fn init(alloc: std.mem.Allocator) !Self {
        \\        var result: Self = .{
        \\            .codepoints = .empty,
        \\            .glyphs = .empty,
        \\        };
        \\        try result.codepoints.ensureTotalCapacity(alloc, 128);
        \\        try result.glyphs.ensureTotalCapacity(alloc, 128);
        \\        try reloadMetrics();
        \\        return result;
        \\    }
        \\};
        \\fn reloadMetrics() !void {}
        \\
    );
    defer freeProblems(gpa, &problems);
    // Both `codepoints` and `glyphs` acquires lack errdefer covering
    // the subsequent try.
    try std.testing.expectEqual(@as(usize, 2), problems.items.len);
}

test "missing-errdefer-on-out-param: with errdefer per acquire doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Self = struct {
        \\    codepoints: std.AutoHashMap(u32, u32),
        \\    glyphs: std.AutoHashMap(u32, u32),
        \\    pub fn init(alloc: std.mem.Allocator) !Self {
        \\        var result: Self = .{ .codepoints = .empty, .glyphs = .empty };
        \\        try result.codepoints.ensureTotalCapacity(alloc, 128);
        \\        errdefer result.codepoints.deinit(alloc);
        \\        try result.glyphs.ensureTotalCapacity(alloc, 128);
        \\        errdefer result.glyphs.deinit(alloc);
        \\        try reloadMetrics();
        \\        return result;
        \\    }
        \\};
        \\fn reloadMetrics() !void {}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "missing-errdefer-on-out-param: no later try doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Self = struct {
        \\    codepoints: std.AutoHashMap(u32, u32),
        \\    pub fn init(alloc: std.mem.Allocator) !Self {
        \\        var result: Self = .{ .codepoints = .empty };
        \\        try result.codepoints.ensureTotalCapacity(alloc, 128);
        \\        return result;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "missing-errdefer-on-out-param: non-canonical out-name (e.g. xyz) doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn build(alloc: std.mem.Allocator) !void {
        \\    var xyz: std.ArrayList(u8) = .empty;
        \\    try xyz.ensureTotalCapacity(alloc, 8);
        \\    _ = try otherFallible();
        \\}
        \\fn otherFallible() !void {}
        \\
    );
    defer freeProblems(gpa, &problems);
    // `xyz` not a canonical out-name, and the chain is only one
    // segment (`xyz.ensureTotalCapacity`, no field access in
    // between) — the rule requires `<out>.<field>.<method>`.
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "missing-errdefer-on-out-param: `out` and `r` canonical names also work" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Self = struct {
        \\    list: std.ArrayList(u8),
        \\    pub fn buildOut(alloc: std.mem.Allocator) !Self {
        \\        var out: Self = .{ .list = .empty };
        \\        try out.list.ensureTotalCapacity(alloc, 8);
        \\        _ = try otherFallible();
        \\        return out;
        \\    }
        \\    pub fn buildR(alloc: std.mem.Allocator) !Self {
        \\        var r: Self = .{ .list = .empty };
        \\        try r.list.ensureTotalCapacity(alloc, 8);
        \\        _ = try otherFallible();
        \\        return r;
        \\    }
        \\};
        \\fn otherFallible() !void {}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 2), problems.items.len);
}
