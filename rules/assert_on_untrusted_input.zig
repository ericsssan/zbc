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

const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const lexer = @import("../lexer.zig");
const testing = @import("../testing.zig");
const matchParen = lexer.matchParen;
const skipNestedFn = lexer.skipNestedFn;

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .assert_on_untrusted_input)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = lexer.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        try checkFn(gpa, tree, cache, fn_entry.proto, fn_entry.name_token, fn_entry.body, problems);
    }
}

fn checkFn(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    proto: Ast.full.FnProto,
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

    // Skip when the fn doesn't return an error union — the
    // canonical "external untrusted input" decoder signals
    // invalid data via `error.Invalid…`.  A fn returning
    // `usize` / `void` / `T` is an INTERNAL helper whose caller
    // is responsible for input validity (e.g. TigerBeetle's
    // ewah decode_chunk: caller pre-validates chunk alignment).
    if (!returnsErrorUnion(tree, proto)) return;

    const bindings = try cache.localBindings(proto, body);

    // Collect param names whose declared type starts with `[` (slice
    // or array type), tolerating an optional `const` prefix.
    var params: std.ArrayListUnmanaged([]const u8) = .empty;
    defer params.deinit(gpa);
    for (bindings.items) |b| {
        if (b.origin != .param) continue;
        if (b.rhs_first > b.rhs_last) continue;
        var ty: Ast.TokenIndex = b.rhs_first;
        if (tags[ty] == .keyword_const and ty < b.rhs_last) ty += 1;
        if (tags[ty] != .l_bracket) continue;
        try params.append(gpa, b.name);
    }
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
        // Length-precondition skip: `assert(<param>.len <op> <N>);`
        // is a defensive contract check — caller is expected to
        // pre-validate, and the fn would still do further parsing
        // afterwards.  Distinct from out-of-bounds index asserts
        // like `assert(buf[idx] == X);` which DO crash on bad data.
        if (isLengthPreconditionAssert(tree, t + 2, cp - 1, params.items)) {
            t = cp;
            continue;
        }
        // Path/semantic-precondition skip: `assert(<path-named-param>[0] == <char-lit>);`
        // — a constant-index byte check on a string-named param
        // (`path`, `file_path`, `url`, `name`, `key`, etc.).  These
        // are caller-validated structural invariants on text inputs
        // (e.g., "absolute path begins with /"), not data-derived
        // out-of-bounds reads.  Distinct from byte-stream parsing
        // (`buffer[0] == 0xFF`) which we DO fire on — magic-byte
        // sanity checks against attacker-controlled bytes need to be
        // converted to explicit validation.
        if (isSemanticStringPreconditionAssert(tree, t + 2, cp - 1, params.items)) {
            t = cp;
            continue;
        }
        try report(gpa, problems, tree, t);
        t = cp;
    }
}

/// True iff the fn's return type starts with `!` (or has `!` in
/// its tokens — handles `error{X,Y}!T` forms too).  Used to
/// distinguish external decoders (`fn decode(buf) !T`) from
/// internal helpers (`fn decode_chunk(buf) usize`).
fn returnsErrorUnion(tree: *const Ast, proto: Ast.full.FnProto) bool {
    const rt = proto.ast.return_type.unwrap() orelse return false;
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(rt);
    if (first > 0 and tags[first - 1] == .bang) return true;
    const last = tree.lastToken(rt);
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        if (tags[t] == .bang) return true;
    }
    return false;
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
/// True iff the assert expression is a LENGTH precondition on
/// a parameter — `<param>.len > <N>` / `<param>.len >= <N>` /
/// `<param>.len % <N> == 0` / etc.  These are defensive contract
/// checks (caller pre-validates); they don't trip on crafted
/// bytes any differently than caller-side validation would.
///
/// The DANGEROUS asserts the rule wants to catch are
/// out-of-bounds-derived checks: `assert(buf[idx] == ...)`,
/// `assert(parse_tag(buf) == .X)` etc.  Those panic on
/// untrusted input.
fn isLengthPreconditionAssert(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    params: []const []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    // Walk tokens looking for `<param-ident> . len`.  If found AND
    // no `[` (index-access) appears in the expression, treat as
    // length-precondition.
    var saw_param_len = false;
    var t: Ast.TokenIndex = start;
    while (t + 2 <= end) : (t += 1) {
        if (tags[t] == .l_bracket) return false; // index-access — too dangerous
        if (tags[t] != .identifier) continue;
        if (t > 0 and tags[t - 1] == .period) continue;
        const name = tree.tokenSlice(t);
        var is_param = false;
        for (params) |p| if (std.mem.eql(u8, p, name)) {
            is_param = true;
            break;
        };
        if (!is_param) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (std.mem.eql(u8, tree.tokenSlice(t + 2), "len")) {
            saw_param_len = true;
        }
    }
    return saw_param_len;
}

/// True iff the assert expression is a semantic-string precondition
/// of the form `<path-named-param>[<int-literal>] <cmp> <char-lit>`.
/// Param-name allowlist: text-shaped slices (path / file_path /
/// url / name / key / ext / suffix / prefix / dir / dirname /
/// basename / filename).  Byte-stream params (buffer / buf / bytes
/// / data / input / wire / pkt / packet / msg / frame) keep firing
/// — magic-byte sanity checks on attacker-controlled bytes need
/// explicit `if (...) return error.X;` validation.
fn isSemanticStringPreconditionAssert(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    params: []const []const u8,
) bool {
    _ = params;
    const tags = tree.tokens.items(.tag);
    var saw_non_const_bracket = false;
    var found = false;
    var t: Ast.TokenIndex = start;
    while (t + 3 <= end) : (t += 1) {
        if (tags[t] != .l_bracket) continue;
        if (tags[t + 1] != .number_literal or tags[t + 2] != .r_bracket) {
            saw_non_const_bracket = true;
            continue;
        }
        if (t == 0 or tags[t - 1] != .identifier) continue;
        const name = tree.tokenSlice(t - 1);
        if (!isSemanticStringName(name)) continue;
        found = true;
    }
    return found and !saw_non_const_bracket;
}

fn isSemanticStringName(name: []const u8) bool {
    const list = [_][]const u8{
        "path",       "file_path",  "filePath", "url",
        "name",       "key",        "ext",      "suffix",
        "prefix",     "dir",        "dirname",  "basename",
        "filename",   "label",      "ident",    "identifier",
        "text",       "str",        "string",
    };
    for (list) |s| if (std.mem.eql(u8, s, name)) return true;
    return false;
}

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
    return testing.runRule(gpa, check, src);
}

const freeProblems = testing.freeProblems;

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

test "assert-on-untrusted-input: assert with index-access on slice-typed param fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\fn assert(_: bool) void {}
        \\pub fn decode_frame(frame: []const u8) !void {
        \\    assert(frame[0] == 0xCA);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "assert-on-untrusted-input: pure length precondition doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\fn assert(_: bool) void {}
        \\pub fn decode_frame(frame: []const u8) !void {
        \\    assert(frame.len > 8);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
