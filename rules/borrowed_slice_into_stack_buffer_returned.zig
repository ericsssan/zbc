//! Borrowed-slice-into-stack-buffer-returned detector — a stack-
//! local `var <buf>: [N]<T> = undefined;` is passed to a known
//! aliasing parser (`SemanticVersion.parse`, etc.), and the
//! returned value (which holds slices INTO `<buf>`) flows out of
//! the fn via `return` — leaving the caller with a struct whose
//! slice fields point at the now-dead `<buf>`.
//!
//! Real-world: ziglang/zig#25713 — `std.zig.system.resolveTargetQuery`
//! parsed a kernel version into `SemanticVersion`, returned the
//! result whose `.pre` / `.build` fields aliased a stack buffer
//! freed at function return.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Collect stack-array locals: `var <buf>: [...]<T> =
//!      undefined;` declarations.
//!   3. Find `const <X> = <T>.parse(<expr>)` (or `try
//!      <T>.parse(...)`) where `<expr>` mentions one of the
//!      stack buffers.  Track `<X>`.
//!   4. If the fn body contains `return <X>` or `return <expr
//!      mentioning X>`, fire on the `return`.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");

const lexer = @import("../lexer.zig");
const matchBrace = lexer.matchBrace;
const matchParen = lexer.matchParen;
const findStmtSemicolon = lexer.findStmtSemicolon;
const skipNestedFn = lexer.skipNestedFn;
const returnsType = lexer.returnsType;
const fnProto = lexer.fnProto;
const bodyOf = lexer.bodyOf;

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .borrowed_slice_into_stack_buffer_returned)) return;

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

    var stack_bufs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer stack_bufs.deinit(gpa);
    try collectStackArrayLocals(gpa, tree, first, last, &stack_bufs);
    if (stack_bufs.items.len == 0) return;

    // Find `const <X> = ... <T>.parse(<expr-mentioning-buf>) ...`
    // bindings.
    var tainted: std.ArrayListUnmanaged([]const u8) = .empty;
    defer tainted.deinit(gpa);
    var t: Ast.TokenIndex = first;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_const and tags[t] != .keyword_var) continue;
        if (tags[t + 1] != .identifier) continue;
        // Walk to `=`.
        var after_name: Ast.TokenIndex = t + 2;
        if (after_name <= last and tags[after_name] == .colon) {
            var d: u32 = 0;
            while (after_name <= last) : (after_name += 1) {
                switch (tags[after_name]) {
                    .l_paren, .l_brace, .l_bracket => d += 1,
                    .r_paren, .r_brace, .r_bracket => if (d > 0) {
                        d -= 1;
                    },
                    .equal => if (d == 0) break,
                    else => {},
                }
            }
        }
        if (after_name > last or tags[after_name] != .equal) continue;
        const sc = findStmtSemicolon(tags, after_name + 1, last) orelse continue;
        // RHS contains `<KnownAliasingType>.parse(` ?
        const parse_call = findParseCall(tree, tags, after_name + 1, sc) orelse {
            t = sc;
            continue;
        };
        // Inside the parse call's args, does it mention a stack buf?
        const cp = matchParen(tags, parse_call + 1, last) orelse {
            t = sc;
            continue;
        };
        if (!callArgsMentionStackBuf(tree, parse_call + 2, cp - 1, stack_bufs.items)) {
            t = sc;
            continue;
        }
        try tainted.append(gpa, tree.tokenSlice(t + 1));
        t = sc;
    }
    if (tainted.items.len == 0) return;

    // Find `return <expr mentioning tainted>`.
    t = first;
    while (t + 1 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_return) continue;
        const sc = findStmtSemicolon(tags, t + 1, last) orelse continue;
        if (returnMentionsTainted(tree, t + 1, sc, tainted.items)) |n| {
            try report(gpa, problems, tree, t, n);
        }
        t = sc;
    }
}

/// Collect `var <name>: [<expr>]<T> = undefined;` declarations.
fn collectStackArrayLocals(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_var) continue;
        if (tags[t + 1] != .identifier) continue;
        if (tags[t + 2] != .colon) continue;
        if (tags[t + 3] != .l_bracket) continue;
        // Type is `[<expr>]<T>` — array, not slice.
        try out.append(gpa, tree.tokenSlice(t + 1));
    }
}

/// Find a call shaped `<Aliasing-Type>.parse(`.  Restricted to a
/// narrow allowlist of known-aliasing parser types — most
/// `.parse()` methods return owned values (or numbers), so a
/// general "any .parse" match produces too many FPs.
fn findParseCall(
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var t: Ast.TokenIndex = start;
    while (t + 1 <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "parse")) continue;
        if (t > 0 and tags[t - 1] != .period) continue;
        if (t + 1 > end or tags[t + 1] != .l_paren) continue;
        // Receiver (token before the `.`) must be in the
        // known-aliasing-parser allowlist.
        if (t < 2 or tags[t - 2] != .identifier) continue;
        if (!isAliasingParserType(tree.tokenSlice(t - 2))) continue;
        return t;
    }
    return null;
}

fn isAliasingParserType(name: []const u8) bool {
    return std.mem.eql(u8, name, "SemanticVersion") or
        std.mem.eql(u8, name, "Uri") or
        std.mem.eql(u8, name, "Url");
}

/// True iff `[start, end]` mentions one of the stack buffer
/// names as an identifier.
fn callArgsMentionStackBuf(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    bufs: []const []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > end) return false;
    var t: Ast.TokenIndex = start;
    while (t <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        const name = tree.tokenSlice(t);
        for (bufs) |b| {
            if (std.mem.eql(u8, b, name)) return true;
        }
    }
    return false;
}

fn returnMentionsTainted(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    tainted: []const []const u8,
) ?[]const u8 {
    const tags = tree.tokens.items(.tag);
    if (start > end) return null;
    var t: Ast.TokenIndex = start;
    while (t <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        const name = tree.tokenSlice(t);
        for (tainted) |n| {
            if (std.mem.eql(u8, n, name)) return n;
        }
    }
    return null;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    return_tok: Ast.TokenIndex,
    tainted_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`return <expr mentioning {s}>` — `{s}` came from a `.parse(...)` call on a stack-local buffer; parsers like `SemanticVersion.parse` populate `.pre` / `.build` / similar fields with slices INTO their input, which dies at fn return.  Clone the borrowed sub-slices or strip them (`.pre = null; .build = null;`) before returning",
        .{ tainted_name, tainted_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "borrowed-slice-into-stack-buffer-returned",
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

test "borrowed-slice-into-stack-buffer-returned: SemanticVersion.parse pattern fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const SemanticVersion = struct {
        \\    pre: ?[]const u8 = null,
        \\    build: ?[]const u8 = null,
        \\    pub fn parse(_: []const u8) SemanticVersion { return .{}; }
        \\};
        \\pub fn detect() SemanticVersion {
        \\    var buf: [64]u8 = undefined;
        \\    const ver = SemanticVersion.parse(&buf);
        \\    return ver;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
    try std.testing.expectEqualStrings("borrowed-slice-into-stack-buffer-returned", problems.items[0].rule_id);
}

test "borrowed-slice-into-stack-buffer-returned: parse on a non-stack-buf doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const SemanticVersion = struct {
        \\    pub fn parse(_: []const u8) SemanticVersion { return .{}; }
        \\};
        \\pub fn detect(text: []const u8) SemanticVersion {
        \\    const ver = SemanticVersion.parse(text);
        \\    return ver;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "borrowed-slice-into-stack-buffer-returned: parse result not returned doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const SemanticVersion = struct {
        \\    pub fn parse(_: []const u8) SemanticVersion { return .{}; }
        \\};
        \\pub fn detect() void {
        \\    var buf: [64]u8 = undefined;
        \\    const ver = SemanticVersion.parse(&buf);
        \\    _ = ver;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
