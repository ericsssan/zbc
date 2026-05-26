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

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("../tokens.zig");
const local = @import("../local_bindings.zig");
const query = @import("../token_query.zig");
const problem_mod = @import("../problem.zig");
const testing = @import("../testing.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const Atom = query.Atom;
const R = "borrowed-slice-into-stack-buffer-returned";

// `<AliasingType>.parse(` anywhere in a binding's RHS.
const parse_call = &[_]Atom{
    .{ .pred = isAliasingParserType },
    .{ .tok = .period },
    .{ .text = "parse" },
    .{ .tok = .l_paren },
};

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .borrowed_slice_into_stack_buffer_returned)) return;
    try lexer.forEachFnCached(gpa, tree, cache, problems, checkFn);
}

fn checkFn(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    proto: Ast.full.FnProto,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    // Cheap pre-scan: no return → nothing to escape, no fire possible.
    if (!lexer.hasTokenInRange(tags, first, last, .keyword_return)) return;

    const bindings = try cache.localBindings(proto, body);

    // Pass 1: stack array locals.
    // Shape: `var <name>: [<...>]<T> = undefined;`.  local.zig doesn't
    // store the type annotation, but the syntax around name_token
    // gives it away: name_token+1 is `:` and name_token+2 is `[`.
    // RHS is the identifier "undefined" (classified as .literal by
    // local.zig).
    var stack_bufs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer stack_bufs.deinit(gpa);
    for (bindings.items) |b| {
        if (b.is_const) continue;
        if (b.origin != .literal) continue;
        if (b.name_token + 2 > last) continue;
        if (tags[b.name_token + 1] != .colon) continue;
        if (tags[b.name_token + 2] != .l_bracket) continue;
        // RHS sanity-check: "undefined".
        if (!std.mem.eql(u8, tree.tokenSlice(b.rhs_first), "undefined")) continue;
        try stack_bufs.append(gpa, b.name);
    }
    if (stack_bufs.items.len == 0) return;

    // Pass 2: tainted bindings.
    // Shape: `[const|var] <X> = ...<AliasingType>.parse(<expr mentioning buf>)...`.
    var tainted: std.ArrayListUnmanaged([]const u8) = .empty;
    defer tainted.deinit(gpa);
    for (bindings.items) |b| {
        if (b.origin == .param) continue;
        // Find the parse-call's `(` in the RHS, then check its args.
        // The parse_call pattern's last atom is `.l_paren`, so the
        // match's end token IS the `(`.
        const parse_m = findFirstMatchInRange(tree, parse_call, b.rhs_first, b.rhs_last) orelse continue;
        const lp = parse_m.end;
        const rp = lexer.matchParen(tags, lp, b.rhs_last) orelse continue;
        if (!rangeMentionsAny(tree, lp + 1, rp - 1, stack_bufs.items)) continue;
        try tainted.append(gpa, b.name);
    }
    if (tainted.items.len == 0) return;

    // Pass 3: scan returns for any tainted ident.
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_return) continue;
        const sc = lexer.findStmtSemicolon(tags, t + 1, last) orelse continue;
        if (sc <= t + 1) continue;
        if (rangeMentionsName(tree, t + 1, sc - 1, tainted.items)) |n| {
            try report(gpa, problems, tree, t, n);
        }
        t = sc;
    }
}

/// Find the first match of `atoms` in `[start, end]` via a forward
/// scan.  No scope/defer/nested-fn skipping — used to scan a single
/// binding's RHS where those concerns don't apply.
fn findFirstMatchInRange(
    tree: *const Ast,
    atoms: []const Atom,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
) ?query.Match {
    if (start > end) return null;
    var t: Ast.TokenIndex = start;
    while (t <= end) : (t += 1) {
        if (query.matchAt(tree, atoms, t, end, null)) |m| return m;
    }
    return null;
}

/// True iff `[start, end]` mentions any name in `names` as an
/// identifier.
fn rangeMentionsAny(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex, names: []const []const u8) bool {
    const tags = tree.tokens.items(.tag);
    if (start > end) return false;
    var t: Ast.TokenIndex = start;
    while (t <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        const id = tree.tokenSlice(t);
        for (names) |n| if (std.mem.eql(u8, n, id)) return true;
    }
    return false;
}

/// Like rangeMentionsAny but returns the matched name on hit.
fn rangeMentionsName(tree: *const Ast, start: Ast.TokenIndex, end: Ast.TokenIndex, names: []const []const u8) ?[]const u8 {
    const tags = tree.tokens.items(.tag);
    if (start > end) return null;
    var t: Ast.TokenIndex = start;
    while (t <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        const id = tree.tokenSlice(t);
        for (names) |n| if (std.mem.eql(u8, n, id)) return n;
    }
    return null;
}

fn isAliasingParserType(name: []const u8) bool {
    return std.mem.eql(u8, name, "SemanticVersion") or
        std.mem.eql(u8, name, "Uri") or
        std.mem.eql(u8, name, "Url");
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
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, return_tok),
        .end = Pos.fromTokenEnd(tree, return_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "SemanticVersion.parse pattern fires" {
    try testing.expectFires(check, R,
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
    );
}

test "parse on a non-stack-buf doesn't fire" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\const SemanticVersion = struct {
        \\    pub fn parse(_: []const u8) SemanticVersion { return .{}; }
        \\};
        \\pub fn detect(text: []const u8) SemanticVersion {
        \\    const ver = SemanticVersion.parse(text);
        \\    return ver;
        \\}
    );
}

test "parse result not returned doesn't fire" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\const SemanticVersion = struct {
        \\    pub fn parse(_: []const u8) SemanticVersion { return .{}; }
        \\};
        \\pub fn detect() void {
        \\    var buf: [64]u8 = undefined;
        \\    const ver = SemanticVersion.parse(&buf);
        \\    _ = ver;
        \\}
    );
}
