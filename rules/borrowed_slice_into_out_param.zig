//! Borrowed-slice-into-out-param detector — `defer <X>.deinit()`
//! (or `defer alloc.free(<X>)`) registers cleanup for a local
//! buffer / arena, and a later write `<out>.* = ...<X>...` (or
//! `<out>.field = ...<X>...`) pushes a view of `<X>` into a
//! caller-visible out-parameter.  When the defer fires on
//! function return, the out-param holds a dangling slice.
//!
//! Real-world: oven-sh/bun#30151 (`query_string.* =
//! ZigString.init(result.query_string)` where
//! `result.query_string` was sliced from `specifier_utf8`, which
//! `defer specifier_utf8.deinit()` would free on return),
//! #30223 (same fn, sibling out-param), #25563 (`install.ca = .{
//! .str = str }` borrowing parser-arena memory freed by
//! `defer parser.deinit()`).
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Pre-pass: collect names of fn parameters whose declared
//!      type is a pointer (`*T`, `?*T`).  These are the
//!      out-param candidates.
//!   3. Pre-pass: collect `defer <X>.deinit()` and
//!      `defer <alloc>.free(<X>)` cleanup targets.
//!   4. Walk the body for writes `<out>.* = <RHS>` or
//!      `<out>.<field> = <RHS>` where `<out>` is in the param set.
//!   5. If the RHS mentions any deferred name, fire.

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
    if (!config_mod.isEnabled(config, .borrowed_slice_into_out_param)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        if (returnsType(tree, node)) continue;
        var buf: [1]Ast.Node.Index = undefined;
        const fp = fnProto(tree, &buf, node) orelse continue;
        const name_tok = fp.name_token orelse continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkFn(gpa, tree, name_tok, body, problems);
    }
}

fn checkFn(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    name_tok: Ast.TokenIndex,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var pointer_params: std.ArrayListUnmanaged([]const u8) = .empty;
    defer pointer_params.deinit(gpa);
    try collectPointerParams(gpa, tree, name_tok, &pointer_params);
    if (pointer_params.items.len == 0) return;

    var deferred: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deferred.deinit(gpa);
    try collectDeferredNames(gpa, tree, first, last, &deferred);
    if (deferred.items.len == 0) return;

    // Walk body for `<out>.* = <RHS>` and `<out>.<field> = <RHS>`
    // writes where <out> is in pointer_params.
    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .identifier) continue;
        const name = tree.tokenSlice(t);
        if (!isPointerParam(name, pointer_params.items)) continue;
        // `<out>.* = ...` — `.*` is `period_asterisk` (single token).
        var rhs_start: ?Ast.TokenIndex = null;
        if (tags[t + 1] == .period_asterisk) {
            if (t + 2 <= last and tags[t + 2] == .equal) rhs_start = t + 3;
        } else if (tags[t + 1] == .period and t + 3 <= last and
            tags[t + 2] == .identifier and tags[t + 3] == .equal)
        {
            // `<out>.<field> = ...`
            rhs_start = t + 4;
        }
        const rs = rhs_start orelse continue;
        const sc = findStmtSemicolon(tags, rs, last) orelse continue;
        // Does RHS mention any deferred name?
        if (rhsMentionsDeferred(tree, rs, sc - 1, deferred.items)) |dn| {
            try report(gpa, problems, tree, t, name, dn);
        }
        t = sc;
    }
}

fn collectPointerParams(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    name_tok: Ast.TokenIndex,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    const tags = tree.tokens.items(.tag);
    const tok_count: u32 = @intCast(tree.tokens.len);
    if (name_tok + 1 >= tok_count) return;
    if (tags[name_tok + 1] != .l_paren) return;
    const last: Ast.TokenIndex = tok_count - 1;
    const cp = matchParen(tags, name_tok + 1, last) orelse return;
    var t: Ast.TokenIndex = name_tok + 2;
    var paren: u32 = 0;
    while (t < cp) : (t += 1) {
        switch (tags[t]) {
            .l_paren => paren += 1,
            .r_paren => if (paren > 0) {
                paren -= 1;
            },
            .identifier => if (paren == 0) {
                if (t + 1 < cp and tags[t + 1] == .colon) {
                    // Look for `*` or `?*` in the type prefix.
                    var ty: Ast.TokenIndex = t + 2;
                    if (ty < cp and tags[ty] == .question_mark) ty += 1;
                    if (ty < cp and tags[ty] == .asterisk) {
                        try out.append(gpa, tree.tokenSlice(t));
                    }
                }
            },
            else => {},
        }
    }
}

fn isPointerParam(name: []const u8, params: []const []const u8) bool {
    for (params) |p| {
        if (std.mem.eql(u8, p, name)) return true;
    }
    return false;
}

/// Collect names registered for cleanup via `defer <X>.deinit()`,
/// `defer <X>.deinit(...)`, or `defer <alloc>.free(<X>)`.
fn collectDeferredNames(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] != .keyword_defer) continue;
        if (tags[t + 1] != .identifier) continue;
        // `defer <X>.deinit(...)` shape.
        if (tags[t + 2] == .period and t + 4 <= last and
            tags[t + 3] == .identifier and tags[t + 4] == .l_paren)
        {
            const m = tree.tokenSlice(t + 3);
            if (std.mem.eql(u8, m, "deinit") or std.mem.eql(u8, m, "close")) {
                try out.append(gpa, tree.tokenSlice(t + 1));
                continue;
            }
            // `defer <alloc>.free(<X>)` — the freed thing is the
            // arg, not the receiver.
            if (std.mem.eql(u8, m, "free")) {
                if (t + 5 <= last and tags[t + 5] == .identifier) {
                    try out.append(gpa, tree.tokenSlice(t + 5));
                }
                continue;
            }
        }
    }
}

/// True iff `[start, end]` mentions one of the deferred names.
/// Returns the matched name on hit.
fn rhsMentionsDeferred(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    deferred: []const []const u8,
) ?[]const u8 {
    const tags = tree.tokens.items(.tag);
    if (start > end) return null;
    var t: Ast.TokenIndex = start;
    while (t <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        const name = tree.tokenSlice(t);
        for (deferred) |d| {
            if (std.mem.eql(u8, d, name)) return d;
        }
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
    write_tok: Ast.TokenIndex,
    out_name: []const u8,
    deferred_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "write into out-param `{s}` uses `{s}` — `{s}` is registered for cleanup via `defer ... .deinit()`/`.free()`, so the out-param holds a dangling slice once the fn returns and the defer fires.  Clone the value with the caller's allocator before assigning",
        .{ out_name, deferred_name, deferred_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "borrowed-slice-into-out-param",
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

test "borrowed-slice-into-out-param: defer arena.deinit + out-param write using arena fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const ZigString = struct {
        \\    pub fn init(_: anytype) ZigString { return .{}; }
        \\};
        \\pub fn parse(out: *ZigString, gpa_alloc: std.mem.Allocator) !void {
        \\    var arena = std.heap.ArenaAllocator.init(gpa_alloc);
        \\    defer arena.deinit();
        \\    out.* = ZigString.init(arena);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
    try std.testing.expectEqualStrings("borrowed-slice-into-out-param", problems.items[0].rule_id);
}

test "borrowed-slice-into-out-param: defer alloc.free(X) + out-param write using X fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Str = struct { ptr: usize };
        \\pub fn parse(install: *Str, alloc: std.mem.Allocator) !void {
        \\    const str = try alloc.alloc(u8, 4);
        \\    defer alloc.free(str);
        \\    install.* = .{ .ptr = @intFromPtr(str.ptr) };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expect(problems.items.len >= 1);
}

test "borrowed-slice-into-out-param: out-param not pointer doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn parse(name: []const u8) !void {
        \\    var buf = name;
        \\    defer _ = buf;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "borrowed-slice-into-out-param: no defer doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn parse(out: *[]const u8, src: []const u8) !void {
        \\    out.* = src;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
