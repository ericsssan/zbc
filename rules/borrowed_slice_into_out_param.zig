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

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("../lexer.zig");
const local = @import("../local.zig");
const query = @import("../query.zig");
const problem_mod = @import("../problem.zig");
const testing = @import("../testing.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const Atom = query.Atom;
const R = "borrowed-slice-into-out-param";

// `defer <X>.<deinit|close>(...)` — $0 = X (the cleanup receiver,
// which is what becomes invalid after the defer fires).
const defer_cleanup = &[_]Atom{
    .{ .tok = .keyword_defer },
    .{ .capture = 0 },
    .{ .tok = .period },
    .{ .pred = isDeinitOrClose },
    .{ .tok = .l_paren },
};

// `defer <_>.free(<X>...)` — the freed thing is the FIRST ARG,
// not the receiver.  $0 = the freed name.
const defer_free = &[_]Atom{
    .{ .tok = .keyword_defer },
    .{ .tok = .identifier },
    .{ .tok = .period },
    .{ .text = "free" },
    .{ .tok = .l_paren },
    .{ .capture = 0 },
};

// `<out>.* = ...` OR `<out>.<field> = ...` — $0 = out.
const write_via_out = &[_]Atom{
    .{ .capture = 0 },
    .{ .any_of = &[_][]const Atom{
        &[_]Atom{ .{ .tok = .period_asterisk }, .{ .tok = .equal } },
        &[_]Atom{ .{ .tok = .period }, .{ .tok = .identifier }, .{ .tok = .equal } },
    } },
};

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .borrowed_slice_into_out_param)) return;
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

    // Cheap pre-scan: any `defer` keyword at all?  Without one the
    // rule can never fire, so skip the binding-walk cost.
    if (!lexer.hasTokenInRange(tags, first, last, .keyword_defer)) return;

    const bindings = try cache.localBindings(proto, body);

    // Pointer params — bindings with .param origin whose declared
    // type starts with `*` or `?*`.
    var pointer_params: std.ArrayListUnmanaged([]const u8) = .empty;
    defer pointer_params.deinit(gpa);
    for (bindings.items) |b| {
        if (b.origin != .param) continue;
        if (!isPointerType(tags, b.rhs_first, b.rhs_last)) continue;
        try pointer_params.append(gpa, b.name);
    }
    if (pointer_params.items.len == 0) return;

    // Deferred names registered for cleanup.  Single pass over
    // `defer` keywords; classify each.  Skips nested fn bodies so
    // a `defer` inside `const f = struct { fn g() void { defer ... } }`
    // doesn't pollute the outer fn's deferred-name set.
    var deferred: std.ArrayListUnmanaged([]const u8) = .empty;
    defer deferred.deinit(gpa);
    var t: Ast.TokenIndex = first;
    while (t <= last) {
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFn(tags, t, last);
            t = if (t < last) t + 1 else last + 1;
            continue;
        }
        if (tags[t] != .keyword_defer) {
            t += 1;
            continue;
        }
        if (query.matchAt(tree, defer_cleanup, t, last, null)) |m| {
            try deferred.append(gpa, m.captureText(tree, 0).?);
            t = m.end + 1;
            continue;
        }
        if (query.matchAt(tree, defer_free, t, last, null)) |m| {
            try deferred.append(gpa, m.captureText(tree, 0).?);
            t = m.end + 1;
            continue;
        }
        t += 1;
    }
    if (deferred.items.len == 0) return;

    // Find writes through pointer params; check RHS for any deferred name.
    try scanWrites(gpa, tree, write_via_out, first, last, pointer_params.items, deferred.items, problems);
}

fn scanWrites(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    atoms: []const Atom,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
    pointer_params: []const []const u8,
    deferred: []const []const u8,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const writes = try query.findAllInBody(gpa, tree, atoms, first, last);
    defer gpa.free(writes);
    for (writes) |w| {
        const out_name = w.captureText(tree, 0).?;
        if (!isPointerParam(out_name, pointer_params)) continue;
        const sc = lexer.findStmtSemicolon(tags, w.end + 1, last) orelse continue;
        if (sc <= w.end + 1) continue;
        const dn = rhsMentionsDeferred(tree, w.end + 1, sc - 1, deferred) orelse continue;
        try report(gpa, problems, tree, w.start, out_name, dn);
    }
}

/// True iff the type expression at `[first, last]` starts with `*`
/// or `?*` — the conservative "this looks like an out-pointer param" check.
fn isPointerType(tags: []const std.zig.Token.Tag, first: Ast.TokenIndex, last: Ast.TokenIndex) bool {
    if (first > last) return false;
    var t: Ast.TokenIndex = first;
    if (tags[t] == .question_mark) {
        if (t + 1 > last) return false;
        t += 1;
    }
    return tags[t] == .asterisk;
}

fn isPointerParam(name: []const u8, params: []const []const u8) bool {
    for (params) |p| if (std.mem.eql(u8, p, name)) return true;
    return false;
}

fn isDeinitOrClose(name: []const u8) bool {
    return std.mem.eql(u8, name, "deinit") or std.mem.eql(u8, name, "close");
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
        for (deferred) |d| if (std.mem.eql(u8, d, name)) return d;
    }
    return null;
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
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, write_tok),
        .end = Pos.fromTokenEnd(tree, write_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "defer arena.deinit + out-param write using arena fires" {
    try testing.expectFires(check, R,
        \\const std = @import("std");
        \\const ZigString = struct {
        \\    pub fn init(_: anytype) ZigString { return .{}; }
        \\};
        \\pub fn parse(out: *ZigString, gpa_alloc: std.mem.Allocator) !void {
        \\    var arena = std.heap.ArenaAllocator.init(gpa_alloc);
        \\    defer arena.deinit();
        \\    out.* = ZigString.init(arena);
        \\}
    );
}

test "defer alloc.free(X) + out-param write using X fires" {
    try testing.expectFires(check, R,
        \\const std = @import("std");
        \\const Str = struct { ptr: usize };
        \\pub fn parse(install: *Str, alloc: std.mem.Allocator) !void {
        \\    const str = try alloc.alloc(u8, 4);
        \\    defer alloc.free(str);
        \\    install.* = .{ .ptr = @intFromPtr(str.ptr) };
        \\}
    );
}

test "out-param not pointer doesn't fire" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\pub fn parse(name: []const u8) !void {
        \\    var buf = name;
        \\    defer _ = buf;
        \\}
    );
}

test "no defer doesn't fire" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\pub fn parse(out: *[]const u8, src: []const u8) !void {
        \\    out.* = src;
        \\}
    );
}
