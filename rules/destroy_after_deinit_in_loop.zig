//! oven-sh/bun#29879 detector — `for (list.items) |h| { h.deinit(); }`
//! inside a destructor where the per-item destroy is missing.
//! When `list` holds heap-allocated pointers (`(*T)`-typed list
//! elements minted via `allocator.create(T)`), the per-iteration
//! `h.deinit()` reclaims the item's fields but the item's own
//! heap descriptor is never freed — every list item leaks.
//!
//! Detection (per fn in {deinit, finalize, destroy} only):
//!   1. Find `for (<expr>) |<h>|` loops (optionally with second
//!      capture for index).
//!   2. Check the loop body has exactly `<h>.deinit();` and NO
//!      `<allocator>.destroy(<h>)` or `.free(<h>)` call.
//!   3. Verify the iterated list's element type is a pointer by
//!      scanning the file source for a field decl whose type
//!      expression contains `(*`.
//!   4. Fire at the loop header.

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("../lexer.zig");
const local = @import("../local.zig");
const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");
const testing = @import("../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

const fnProto = lexer.fnProto;
const bodyOf = lexer.bodyOf;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .destroy_after_deinit_in_loop)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = lexer.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        if (!isDestructorName(tree.tokenSlice(fn_entry.name_token))) continue;
        try checkFn(gpa, tree, cache, fn_entry.proto, fn_entry.body, problems);
    }
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
    const last = tree.lastToken(body);

    const bindings = try cache.localBindings(proto, body);

    for (bindings.items) |b| {
        if (b.origin != .loop_capture) continue;
        // Find the closing `|` of the capture clause (after name_token,
        // possibly past comma-separated extra captures).
        var v: Ast.TokenIndex = b.name_token + 1;
        while (v <= last and tags[v] != .pipe) : (v += 1) {}
        if (v > last) continue;
        const body_start = v + 1;
        const body_end = findLoopBodyEnd(tags, body_start, last) orelse continue;

        if (!bodyHasDeinit(tree, body_start, body_end, b.name)) continue;
        if (bodyHasDestroyOrFree(tree, body_start, body_end, b.name)) continue;

        // List-shape gate: the iterable expression's trailing identifier
        // (e.g. `element_handlers` in `this.element_handlers.items`) is
        // the name of a pointer-list field.  Binding.rhs_last is the
        // last token of the iterable; the `)` is at rhs_last + 1.
        const list_field_name = lastFieldIdentBefore(tree, b.rhs_last + 1) orelse continue;
        if (!isPointerListField(tree, list_field_name)) continue;

        // Report at the `for` keyword.  Walk back from name_token to
        // find the enclosing `keyword_for`.
        const for_tok = findEnclosingFor(tags, b.name_token) orelse continue;
        try report(gpa, problems, tree, for_tok, b.name, list_field_name);
    }
}

/// Walk back from a capture-name token to find the enclosing
/// `keyword_for` / `keyword_while` / `keyword_if`.  Stops at the
/// nearest one.
fn findEnclosingFor(tags: []const std.zig.Token.Tag, name_token: Ast.TokenIndex) ?Ast.TokenIndex {
    if (name_token == 0) return null;
    var t: Ast.TokenIndex = name_token - 1;
    while (t > 0) : (t -= 1) {
        if (tags[t] == .keyword_for) return t;
        if (tags[t] == .keyword_while or tags[t] == .keyword_if) return t;
    }
    return null;
}

/// Walk tokens at `start` to find the end of a for-loop's body.
/// If the body opens with `{`, find the matching `}`.  Otherwise
/// find the terminating `;` at our current paren/brace depth.
fn findLoopBodyEnd(
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    if (start > last) return null;
    if (tags[start] == .l_brace) {
        var depth: u32 = 1;
        var t: Ast.TokenIndex = start + 1;
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

/// True iff the token range `[start, end]` contains a
/// `<capture>.deinit(` call (or related destruction call).
fn bodyHasDeinit(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    capture: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 3 <= end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), capture)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        const m = tree.tokenSlice(t + 2);
        if (std.mem.eql(u8, m, "deinit") or std.mem.eql(u8, m, "finalize")) return true;
    }
    return false;
}

/// True iff the token range contains a `<x>.destroy(<capture>)`,
/// `<x>.free(<capture>)`, `<x>.destroy(<capture>)` style call.
fn bodyHasDestroyOrFree(
    tree: *const Ast,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    capture: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 4 <= end) : (t += 1) {
        if (tags[t] != .period) continue;
        if (tags[t + 1] != .identifier) continue;
        const m = tree.tokenSlice(t + 1);
        if (!std.mem.eql(u8, m, "destroy") and
            !std.mem.eql(u8, m, "free")) continue;
        if (tags[t + 2] != .l_paren) continue;
        if (tags[t + 3] != .identifier) continue;
        if (std.mem.eql(u8, tree.tokenSlice(t + 3), capture)) return true;
    }
    return false;
}

/// Walk back from a token to find the most recent `<identifier>`
/// that immediately precedes a `.items` / `.values` / similar
/// projection.  This gives the list field name on a `<obj>.<field>.items`
/// iterable.  Returns null when the shape doesn't match.
fn lastFieldIdentBefore(tree: *const Ast, close_paren: Ast.TokenIndex) ?[]const u8 {
    const tags = tree.tokens.items(.tag);
    if (close_paren < 4) return null;
    // The iterable looks like `…<field>.items` (or `.values`,
    // `.slice()`, etc.) — last 3 tokens before `)` should be
    // `<field>` `.` `items`/`.values`.
    if (tags[close_paren - 1] != .identifier) return null;
    if (tags[close_paren - 2] != .period) return null;
    if (tags[close_paren - 3] != .identifier) return null;
    const proj = tree.tokenSlice(close_paren - 1);
    if (!std.mem.eql(u8, proj, "items") and
        !std.mem.eql(u8, proj, "values") and
        !std.mem.eql(u8, proj, "keys")) return null;
    return tree.tokenSlice(close_paren - 3);
}

/// Heuristic: scan the file source for a `<field>:` declaration
/// whose type expression contains `(*` — i.e. the list's element
/// type is a pointer.  Loose but accurate for the canonical
/// `field: std.ArrayListUnmanaged(*T) = .{}` pattern.
fn isPointerListField(tree: *const Ast, field_name: []const u8) bool {
    const src = tree.source;
    var pat_buf: [256]u8 = undefined;
    if (field_name.len + 2 > pat_buf.len) return true;
    @memcpy(pat_buf[0..field_name.len], field_name);
    pat_buf[field_name.len] = ':';
    pat_buf[field_name.len + 1] = ' ';
    const pat = pat_buf[0 .. field_name.len + 2];
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, src, idx, pat)) |found| {
        // Look at the next ~120 bytes after the `:` for `(*` or
        // `[*]` / `[]*` substring.
        const end = @min(found + pat.len + 120, src.len);
        const slice = src[found + pat.len .. end];
        if (std.mem.indexOf(u8, slice, "(*") != null) return true;
        if (std.mem.indexOf(u8, slice, "[]*") != null) return true;
        idx = found + pat.len;
    }
    return false;
}

fn isDestructorName(name: []const u8) bool {
    return std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "finalize") or
        std.mem.eql(u8, name, "destroy");
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    for_tok: Ast.TokenIndex,
    capture: []const u8,
    list_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "loop calls `{s}.deinit()` per element of pointer-list `{s}` but never `<allocator>.destroy({s})` — each item's heap descriptor leaks; add `<allocator>.destroy({s});` after the `.deinit()` call",
        .{ capture, list_name, capture, capture },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "destroy-after-deinit-in-loop",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, for_tok),
        .end = Pos.fromTokenEnd(tree, for_tok),
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
    var cache = file_cache_mod.FileCache.init(gpa, &tree);
    defer cache.deinit();
    try check(gpa, &tree, &cache, &config_mod.Default, &problems);
    return problems;
}

const freeProblems = testing.freeProblems;

test "destroy-after-deinit-in-loop: pointer-list loop without destroy fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Handler = struct { pub fn deinit(_: *Handler) void {} };
        \\const Ctx = struct {
        \\    handlers: std.ArrayListUnmanaged(*Handler) = .{},
        \\    pub fn deinit(this: *Ctx) void {
        \\        for (this.handlers.items) |h| {
        \\            h.deinit();
        \\        }
        \\        this.handlers.deinit(std.heap.page_allocator);
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("destroy-after-deinit-in-loop", problems.items[0].rule_id);
}

test "destroy-after-deinit-in-loop: loop body includes destroy is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Handler = struct { pub fn deinit(_: *Handler) void {} };
        \\const Ctx = struct {
        \\    handlers: std.ArrayListUnmanaged(*Handler) = .{},
        \\    pub fn deinit(this: *Ctx) void {
        \\        for (this.handlers.items) |h| {
        \\            h.deinit();
        \\            std.heap.page_allocator.destroy(h);
        \\        }
        \\        this.handlers.deinit(std.heap.page_allocator);
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "destroy-after-deinit-in-loop: value-typed list is OK (no `(*` in decl)" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Handler = struct { pub fn deinit(_: *Handler) void {} };
        \\const Ctx = struct {
        \\    handlers: std.ArrayListUnmanaged(Handler) = .{},
        \\    pub fn deinit(this: *Ctx) void {
        \\        for (this.handlers.items) |*h| {
        \\            h.deinit();
        \\        }
        \\        this.handlers.deinit(std.heap.page_allocator);
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "destroy-after-deinit-in-loop: non-destructor fn is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Handler = struct { pub fn deinit(_: *Handler) void {} };
        \\const Ctx = struct {
        \\    handlers: std.ArrayListUnmanaged(*Handler) = .{},
        \\    pub fn cleanupSome(this: *Ctx) void {
        \\        for (this.handlers.items) |h| {
        \\            h.deinit();
        \\        }
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
