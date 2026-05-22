//! `return switch (<expr>) { ... };` where one arm returns the
//! captured payload bare (`.<Tag> => |v| v`) while a sibling arm
//! clones / allocates a fresh value (`alloc.dupe(...)`, `.clone(...)`,
//! etc.).  The bare arm returns a slice/pointer borrowed from the
//! caller's input — which may be freed while the return value is
//! still in use.
//!
//! Sibling-arm asymmetry is the strongest signal: when one arm
//! goes to the trouble of `alloc.dupe(...)` the author clearly
//! intends the returned value to be owned by the caller's
//! allocator.  An adjacent arm that returns `|v| v` raw is almost
//! always an oversight.
//!
//! Real-world: ghostty-org/ghostty#8358 ("terminal: fix use-after-
//! free in exec") and #7711 (open() accepted arena, returned slice
//! into it that outlived arena).
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Walk for `return switch (` in fn body.
//!   3. Find arms `.<Tag> => |v| <body>` where `<body>` is either
//!      bare `v,` (bare capture return) OR contains an allocator
//!      method call (`<X>.dupe(...)`, `.clone(...)`, etc.).
//!   4. If both a bare-return arm AND a clone arm exist in the
//!      same switch, fire on each bare-return arm.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const lexer = @import("../lexer.zig");
const testing = @import("../testing.zig");
const matchBrace = lexer.matchBrace;
const matchParen = lexer.matchParen;
const skipNestedFn = lexer.skipNestedFn;
const returnsType = lexer.returnsType;
const fnProto = lexer.fnProto;
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
    if (!config_mod.isEnabled(config, .return_borrowed_payload)) return;
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
        if (tags[t] != .keyword_return) continue;
        if (tags[t + 1] != .keyword_switch) continue;
        if (tags[t + 2] != .l_paren) continue;
        const cp = matchParen(tags, t + 2, last) orelse continue;
        if (cp + 1 > last or tags[cp + 1] != .l_brace) continue;
        const sw_body_start = cp + 1;
        const sw_body_end = matchBrace(tags, sw_body_start, last) orelse continue;
        try checkSwitchArms(gpa, tree, sw_body_start + 1, sw_body_end - 1, problems);
        t = sw_body_end;
    }
}

const ArmInfo = struct {
    /// Token of the `.<Tag>` identifier (anchor for diagnostic).
    tag_tok: Ast.TokenIndex,
    is_bare_return: bool,
    has_clone: bool,
};

fn checkSwitchArms(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    var arms: std.ArrayListUnmanaged(ArmInfo) = .empty;
    defer arms.deinit(gpa);

    var t: Ast.TokenIndex = start;
    while (t + 3 <= end) : (t += 1) {
        // Find arm start `.<Tag>` (skip `else`).
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        const tag_tok = t + 1;
        // Find `=>`.
        var fa: Ast.TokenIndex = tag_tok + 1;
        while (fa <= end and tags[fa] != .equal_angle_bracket_right) : (fa += 1) {}
        if (fa > end) break;
        // Optional capture `|v|`.
        var capture_name: ?[]const u8 = null;
        var body_start: Ast.TokenIndex = fa + 1;
        if (body_start <= end and tags[body_start] == .pipe) {
            var p: Ast.TokenIndex = body_start + 1;
            if (p <= end and tags[p] == .asterisk) p += 1;
            if (p <= end and tags[p] == .identifier) {
                capture_name = tree.tokenSlice(p);
            }
            while (p <= end and tags[p] != .pipe) : (p += 1) {}
            if (p > end) break;
            body_start = p + 1;
        }
        if (body_start > end) break;
        // Arm body — block or inline.
        const body_end_inclusive = if (tags[body_start] == .l_brace)
            (matchBrace(tags, body_start, end) orelse break)
        else
            (findArmEndInclusive(tags, body_start, end) orelse break);
        const scan_start = if (tags[body_start] == .l_brace)
            body_start + 1
        else
            body_start;
        const scan_end = if (tags[body_start] == .l_brace)
            body_end_inclusive - 1
        else
            body_end_inclusive;

        const is_bare = if (capture_name) |cap|
            armIsBareReturn(tree, scan_start, scan_end, cap)
        else
            false;
        const has_clone = armHasClone(tree, scan_start, scan_end);
        try arms.append(gpa, .{
            .tag_tok = tag_tok,
            .is_bare_return = is_bare,
            .has_clone = has_clone,
        });
        t = body_end_inclusive;
    }

    // If ANY arm has clone AND there's a bare-return arm, fire on
    // each bare-return arm.
    var any_clone = false;
    for (arms.items) |a| {
        if (a.has_clone) any_clone = true;
    }
    if (!any_clone) return;
    for (arms.items) |a| {
        if (a.is_bare_return) try report(gpa, problems, tree, a.tag_tok);
    }
}

/// True iff the arm's body is JUST `<capture>` (with optional
/// trailing tokens like `,`).  Empty bodies don't count.
fn armIsBareReturn(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    capture: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > end) return false;
    if (tags[start] != .identifier) return false;
    if (!std.mem.eql(u8, tree.tokenSlice(start), capture)) return false;
    // Allow `<capture>` followed by nothing OR by `,` only.
    var t: Ast.TokenIndex = start + 1;
    while (t <= end) : (t += 1) {
        if (tags[t] == .comma) continue;
        // Any other non-trivial token (period, paren, etc.) means
        // there's more going on — not a bare return.
        return false;
    }
    return true;
}

/// True iff the arm contains a clone/allocate method call.
fn armHasClone(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex) bool {
    const tags = tree.tokens.items(.tag);
    if (start > end) return false;
    var t: Ast.TokenIndex = start;
    while (t + 2 <= end) : (t += 1) {
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .l_paren) continue;
        const m = tree.tokenSlice(t + 1);
        if (isAllocOrCloneMethodName(m)) return true;
    }
    return false;
}

fn isAllocOrCloneMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "dupe") or
        std.mem.eql(u8, name, "dupeZ") or
        std.mem.eql(u8, name, "alloc") or
        std.mem.eql(u8, name, "allocSentinel") or
        std.mem.eql(u8, name, "create") or
        std.mem.eql(u8, name, "clone") or
        std.mem.eql(u8, name, "cloneWith") or
        std.mem.eql(u8, name, "allocPrint") or
        std.mem.eql(u8, name, "allocPrintZ") or
        std.mem.eql(u8, name, "toOwnedSlice") or
        std.mem.eql(u8, name, "toOwnedSliceSentinel");
}

fn findArmEndInclusive(
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
            } else return t - 1,
            .l_bracket => bracket += 1,
            .r_bracket => if (bracket > 0) {
                bracket -= 1;
            },
            .comma => if (paren == 0 and brace == 0 and bracket == 0) return t - 1,
            else => {},
        }
    }
    return null;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    tag_tok: Ast.TokenIndex,
) !void {
    const tag = tree.tokenSlice(tag_tok);
    const msg = try std.fmt.allocPrint(
        gpa,
        "`return switch (...) {{ .{s} => |v| v, ... }}` returns the captured payload bare while a sibling arm clones / allocates — the caller's input may be freed while this return value is still in use.  Clone the payload too (e.g. `alloc.dupe(u8, v)` / `try v.clone(alloc)`)",
        .{tag},
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "return-borrowed-payload",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, tag_tok),
        .end = Pos.fromTokenEnd(tree, tag_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    return testing.runRule(gpa, check, src);
}

const freeProblems = testing.freeProblems;

test "return-borrowed-payload: sibling-arm asymmetry fires on bare return" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Cmd = union(enum) {
        \\    direct: []const u8,
        \\    shell: []const u8,
        \\};
        \\pub fn extract(cmd: Cmd, alloc: std.mem.Allocator) ![]const u8 {
        \\    return switch (cmd) {
        \\        .direct => |v| v,
        \\        .shell => |v| try alloc.dupe(u8, v),
        \\    };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("return-borrowed-payload", problems.items[0].rule_id);
}

test "return-borrowed-payload: all arms clone — no fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Cmd = union(enum) { a: []const u8, b: []const u8 };
        \\pub fn extract(cmd: Cmd, alloc: std.mem.Allocator) ![]const u8 {
        \\    return switch (cmd) {
        \\        .a => |v| try alloc.dupe(u8, v),
        \\        .b => |v| try alloc.dupe(u8, v),
        \\    };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "return-borrowed-payload: all arms bare — no fire (no sibling asymmetry signal)" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Cmd = union(enum) { a: []const u8, b: []const u8 };
        \\pub fn extract(cmd: Cmd) []const u8 {
        \\    return switch (cmd) {
        \\        .a => |v| v,
        \\        .b => |v| v,
        \\    };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "return-borrowed-payload: clone via .clone(alloc) also recognized" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Payload = struct {
        \\    pub fn clone(_: *const Payload, _: std.mem.Allocator) !Payload { return .{}; }
        \\};
        \\const Cmd = union(enum) { a: Payload, b: Payload };
        \\pub fn extract(cmd: Cmd, alloc: std.mem.Allocator) !Payload {
        \\    return switch (cmd) {
        \\        .a => |v| v,
        \\        .b => |v| try v.clone(alloc),
        \\    };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}
