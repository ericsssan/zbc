//! Assert-on-untrusted-input detector — `assert(<expr>)` in a
//! parser/decoder fn where `<expr>` references a parameter that
//! looks like raw external bytes (slice or message/block/header
//! parameter).  Crafted input trips the assert → panic / DoS.
//! The fix is `if (<cond>) return error.InvalidX` — proper input
//! validation, not an invariant assertion.
//!
//! Real-world: tigerbeetle/tigerbeetle#3709 (Mach-O fat-arch
//! body offset assert → panic on crafted multiversion binary),
//! #3726 (AMQP frame size assert → panic on bad frame), #2980
//! (grid block release-value assert → panic on bad disk block).
//!
//! TigerStyle: asserts encode INTERNAL invariants known to hold;
//! values from a network packet, file, or peer block are
//! external and MUST be validated as `if (...) return error.X`,
//! never asserted.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Restrict to fns whose name OR parameter set suggests
//!      parsing: name starts with `parse` / `decode` / `from_`
//!      / `read_` / `on_message` / `on_block`, OR has a parameter
//!      named one of {buffer, bytes, data, body, msg, message,
//!      header, frame, packet, block, payload, input, raw}.
//!   3. Scan body for `assert(<expr>)` calls.
//!   4. Fire if `<expr>` references one of the byte-like parameter
//!      names (as identifier or as receiver in `<param>.<field>`
//!      or `<param>[<expr>]`).

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
    if (!config_mod.isEnabled(config, .assert_on_untrusted_input)) return;

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

    // Two stacked signals are required (both must hold):
    //   (a) Fn name starts with a parser/decoder-ish prefix —
    //       narrows to fns the author has self-labeled as
    //       parsing untrusted input.
    //   (b) At least one parameter has an explicit slice type
    //       (`[]const u8`, `[]u8`, `[*]const u8`, `[N]u8`).
    // Either signal alone is too noisy in TigerStyle codebases
    // (asserts are everywhere; parser-named helpers often take
    // already-validated typed wrappers).
    const fn_name = tree.tokenSlice(name_tok);
    if (!isParserName(fn_name)) return;
    var params: std.ArrayListUnmanaged([]const u8) = .empty;
    defer params.deinit(gpa);
    try collectByteLikeParams(gpa, tree, name_tok, &params);
    if (params.items.len == 0) return;

    // Scan body for `assert(<expr>)` calls.
    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "assert")) continue;
        if (tags[t + 1] != .l_paren) continue;
        const cp = matchParen(tags, t + 1, last) orelse continue;
        // Check if the assert's expression mentions a byte-like
        // parameter.
        if (!assertMentionsParam(tree, t + 2, cp - 1, params.items)) {
            t = cp;
            continue;
        }
        try report(gpa, problems, tree, t);
        t = cp;
    }
}

/// Walk forward from the fn name's identifier to find the `(` of
/// the parameter list, then collect parameter names whose declared
/// type is an EXPLICIT slice (`[]const u8`, `[]u8`, `[*]const u8`,
/// `[*]u8`).  Other types — even structured wrappers like
/// `*Message` or `Header` — are too commonly used for INTERNAL
/// invariants in this codebase to be reliably classified as
/// untrusted.
fn collectByteLikeParams(
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
                if (t + 2 < cp and tags[t + 1] == .colon) {
                    // Look at the type token immediately after `:`.
                    // We accept slice (`[`) or sentinel-array
                    // (`[:`) starts.  Skip past any `const`
                    // modifier.
                    var ty: Ast.TokenIndex = t + 2;
                    if (tags[ty] == .keyword_const) ty += 1;
                    if (ty < cp and tags[ty] == .l_bracket) {
                        // `[...]u8`-style slice type.  Accept any
                        // bracket-starting parameter type; the
                        // narrow check is enough to drop structured
                        // wrappers.
                        try out.append(gpa, tree.tokenSlice(t));
                    }
                }
            },
            else => {},
        }
    }
}

fn isParserName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "parse") or
        std.mem.startsWith(u8, name, "decode") or
        std.mem.startsWith(u8, name, "from_bytes") or
        std.mem.startsWith(u8, name, "fromBytes") or
        std.mem.startsWith(u8, name, "from_buffer") or
        std.mem.startsWith(u8, name, "fromBuffer") or
        std.mem.startsWith(u8, name, "from_slice") or
        std.mem.startsWith(u8, name, "fromSlice") or
        std.mem.startsWith(u8, name, "read_header") or
        std.mem.startsWith(u8, name, "readHeader") or
        std.mem.eql(u8, name, "on_message") or
        std.mem.eql(u8, name, "on_block") or
        std.mem.eql(u8, name, "onMessage") or
        std.mem.eql(u8, name, "onBlock");
}

/// True iff `[start, end]` mentions one of the slice-typed
/// parameter names — as a bare identifier OR as the receiver of
/// a `.<field>` / `[<expr>]` access.
fn assertMentionsParam(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    params: []const []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    if (start > end) return false;
    var t: Ast.TokenIndex = start;
    while (t <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        const name = tree.tokenSlice(t);
        for (params) |p| {
            if (std.mem.eql(u8, p, name)) return true;
        }
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
    assert_tok: Ast.TokenIndex,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`assert(...)` in a parser/decoder fn against an expression derived from untrusted input — crafted bytes will trip the assert and panic the process.  Convert to `if (!<cond>) return error.<Invalid>;` (TigerStyle: asserts encode INTERNAL invariants; external input requires explicit validation)",
        .{},
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "assert-on-untrusted-input",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, assert_tok),
        .end = Pos.fromTokenEnd(tree, assert_tok),
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

test "assert-on-untrusted-input: assert on buffer param fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\fn assert(_: bool) void {}
        \\pub fn parse_header(buffer: []const u8) !void {
        \\    assert(buffer[0] == 0xFF);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("assert-on-untrusted-input", problems.items[0].rule_id);
}

test "assert-on-untrusted-input: structured *Message param (NOT a slice) doesn't fire" {
    // Internal-message structured wrappers (`*Message`, `Decoder.Header`,
    // etc.) are too commonly used for internal invariants to be
    // reliably classified as untrusted.  Rule requires an EXPLICIT
    // slice parameter.
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\fn assert(_: bool) void {}
        \\const Message = struct { size: usize };
        \\pub fn decode(message: *Message) !void {
        \\    assert(message.size > 0);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "assert-on-untrusted-input: assert on self.field doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\fn assert(_: bool) void {}
        \\const Self = struct {
        \\    count: usize,
        \\    pub fn parse(self: *Self, buffer: []const u8) !void {
        \\        _ = buffer;
        \\        assert(self.count > 0);
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    // assert references self.count, not buffer — internal invariant.
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "assert-on-untrusted-input: non-parser fn name + no byte-like params → no fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\fn assert(_: bool) void {}
        \\const Self = struct {
        \\    count: usize,
        \\    pub fn tick(self: *Self) void {
        \\        assert(self.count > 0);
        \\        self.count -= 1;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "assert-on-untrusted-input: parser fn without slice param doesn't fire" {
    // Name-signal-only firing was too noisy; rule now requires
    // an explicit slice parameter as the untrusted-input signal.
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\fn assert(_: bool) void {}
        \\pub fn decode_command(cmd: u8) !void {
        \\    assert(cmd < 16);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "assert-on-untrusted-input: assert mentions slice-typed param fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\fn assert(_: bool) void {}
        \\pub fn decode_frame(frame: []const u8) !void {
        \\    assert(frame.len > 8);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}
