//! Sentinel-strip-free-size-mismatch detector — `<alloc>.free(
//! <X>.ptr[0..<X>.len])` (or `<X>.ptr.?[0..<X>.len]`) hand-rolls
//! a `[]u8` slice from a many-item-pointer and slices it to
//! `<X>.len`.  If `<X>` is a sentinel-terminated slice
//! (`[:0]const u8` produced by `dupeZ`, `allocSentinel`, string
//! literals, etc.) the underlying allocation is `len + 1` bytes
//! — but the freed slice is only `len` bytes.  The allocator's
//! free-size check trips with `Allocation size N+1 does not
//! match free size N`.
//!
//! Even when there's no sentinel, the shape is redundant — you
//! should just pass `<X>` to `free` directly.  Either
//! interpretation is a bug.
//!
//! Real-world: ghostty-org/ghostty#8886
//! (`ghostty_string_free` in src/main_c.zig).
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Find `.free(` calls preceded by `.` (allocator method).
//!   3. Match the single argument against the pattern
//!      `<X> . ptr (.?)? [ <expr> . . <X> . len ]`.
//!   4. Fire on the `.free` call.

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
    if (!config_mod.isEnabled(config, .sentinel_strip_free_size_mismatch)) return;

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
        // `.free(` preceded by `.` — allocator method call.
        if (tags[t] != .identifier) continue;
        if (t == 0 or tags[t - 1] != .period) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "free")) continue;
        if (tags[t + 1] != .l_paren) continue;
        const cp = matchParen(tags, t + 1, last) orelse continue;
        // Match arg: `<X> . ptr (.?)? [ <expr> . . <X> . len ]`
        if (matchSentinelStrip(tree, t + 2, cp - 1)) {
            try report(gpa, problems, tree, t);
        }
        t = cp;
    }
}

/// True iff `[start, end]` looks like `<X>.ptr[<lo>..<X>.len]`
/// or `<X>.ptr.?[<lo>..<X>.len]`.
fn matchSentinelStrip(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
) bool {
    const tags = tree.tokens.items(.tag);
    if (end < start + 6) return false;
    if (tags[start] != .identifier) return false;
    const x_name = tree.tokenSlice(start);
    if (tags[start + 1] != .period) return false;
    if (tags[start + 2] != .identifier) return false;
    if (!std.mem.eql(u8, tree.tokenSlice(start + 2), "ptr")) return false;
    // Optional `.?` — TWO tokens: `period` + `question_mark`.
    var t: Ast.TokenIndex = start + 3;
    if (t + 1 <= end and tags[t] == .period and tags[t + 1] == .question_mark) {
        t += 2;
    }
    if (t > end or tags[t] != .l_bracket) return false;
    // Find matching `]`.
    const rb = matchBracket(tags, t, end) orelse return false;
    // Inside `[...]`, look for `.. <X> . len`.
    var u: Ast.TokenIndex = t + 1;
    while (u + 4 <= rb) : (u += 1) {
        if (tags[u] != .ellipsis2) continue;
        if (tags[u + 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(u + 1), x_name)) continue;
        if (tags[u + 2] != .period) continue;
        if (tags[u + 3] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(u + 3), "len")) continue;
        return true;
    }
    return false;
}

fn matchParen(
    tags: []const std.zig.Token.Tag,
    lp: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var depth: u32 = 1;
    var t: Ast.TokenIndex = lp + 1;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_paren => depth += 1,
            .r_paren => {
                depth -= 1;
                if (depth == 0) return t;
            },
            else => {},
        }
    }
    return null;
}

fn matchBracket(
    tags: []const std.zig.Token.Tag,
    lb: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var depth: u32 = 1;
    var t: Ast.TokenIndex = lb + 1;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_bracket => depth += 1,
            .r_bracket => {
                depth -= 1;
                if (depth == 0) return t;
            },
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
    free_tok: Ast.TokenIndex,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`<alloc>.free(<X>.ptr[0..<X>.len])` hand-rolls a non-sentinel slice from a many-item-pointer.  If `<X>` is `[:0]const u8` or another sentinel-terminated slice, the underlying allocation is len+1 bytes — the allocator's free-size check trips.  Either pass `<X>` directly to `free`, or include the sentinel: `<alloc>.free(<X>.ptr.?[0..<X>.len :0])`",
        .{},
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "sentinel-strip-free-size-mismatch",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, free_tok),
        .end = Pos.fromTokenEnd(tree, free_tok),
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

test "sentinel-strip-free-size-mismatch: ghostty_string_free pattern fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Str = struct { ptr: ?[*]const u8, len: usize };
        \\pub fn ghostty_string_free(str: Str, alloc: std.mem.Allocator) void {
        \\    alloc.free(str.ptr.?[0..str.len]);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("sentinel-strip-free-size-mismatch", problems.items[0].rule_id);
}

test "sentinel-strip-free-size-mismatch: bare .ptr[0..len] variant also fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Str = struct { ptr: [*]u8, len: usize };
        \\pub fn release(str: Str, alloc: std.mem.Allocator) void {
        \\    alloc.free(str.ptr[0..str.len]);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "sentinel-strip-free-size-mismatch: alloc.free(slice) directly doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn release(slice: []u8, alloc: std.mem.Allocator) void {
        \\    alloc.free(slice);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "sentinel-strip-free-size-mismatch: alloc.free(slice[0..N]) doesn't fire (not .ptr-based)" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn release(slice: []u8, alloc: std.mem.Allocator) void {
        \\    alloc.free(slice[0..10]);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
