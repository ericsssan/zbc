//! `ez/require-arena-kill-tag` — Layer 1 annotation hygiene rule.
//!
//! Flags `ArenaAllocator.deinit()` (or `ArenaState.deinit()`) call sites
//! that are NOT immediately preceded by a `// @kills_arena(<name>)` line
//! comment.
//!
//! Layer 2 uses these tags to mark arena death points in the CFG so it
//! can verify nothing borrowed from the arena is used past them.
//! Without the tag the analyzer treats the call as an opaque void
//! method and misses the death — silently disabling invariant #2 for
//! that arena.
//!
//! Recognized call shapes:
//!   foo.deinit()
//!   self.arena.deinit()
//!   arena_state.deinit()
//!
//! The tag should name the arena receiver, e.g.
//!   // @kills_arena(self.arena)
//!   self.arena.deinit();

const std = @import("std");
const Ast = std.zig.Ast;
const problem_mod = @import("../problem.zig");
const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

const RULE_ID = "ez/require-arena-kill-tag";

pub const Config = struct {
    severity: problem_mod.Severity = .warning,
    /// Identifier substrings that suggest the receiver is an arena.
    /// Any deinit() on a receiver containing one of these triggers
    /// the check.  Conservative — we'd rather flag too much than miss
    /// a real arena death.
    arena_name_hints: []const []const u8 = &.{
        "arena",
        "Arena",
        "backing",
    },
};

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cfg: Config,
    out: *std.ArrayListUnmanaged(Problem),
) !void {
    if (cfg.severity == .off) return;

    // Walk every node looking for `<receiver>.deinit()` calls.
    // Three tags cover the call/member shapes we care about:
    //   .call_one         — `expr(arg)` with a single arg or none
    //   .call             — `expr(args...)` with multiple
    //   .call_one_comma   — same as call_one but with trailing comma
    //   .call_comma       — same as call but with trailing comma
    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        const tag = tree.nodeTag(node);
        const is_call = switch (tag) {
            .call_one, .call_one_comma, .call, .call_comma => true,
            else => false,
        };
        if (!is_call) continue;

        try checkCall(gpa, tree, cfg, node, out);
    }
}

fn checkCall(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cfg: Config,
    call_node: Ast.Node.Index,
    out: *std.ArrayListUnmanaged(Problem),
) !void {
    // Source-text inspection — robust to Node.Data variant churn.
    const first = tree.firstToken(call_node);
    const last = tree.lastToken(call_node);
    const start = tree.tokens.items(.start)[first];
    const last_start = tree.tokens.items(.start)[last];
    const last_len = tree.tokenSlice(last).len;
    const end: usize = last_start + last_len;
    const text = tree.source[start..end];

    // Find the `.deinit(` suffix. If absent, skip.
    const deinit_paren = std.mem.indexOf(u8, text, ".deinit(") orelse return;

    // `defer <receiver>.deinit()` and `defer { ... arena.deinit() ... }`
    // are known-safe scope-exit patterns — the defer pins cleanup to
    // function/block exit and a borrow obtained INSIDE the scope can't
    // escape past the defer firing.  Skip — Layer 2 doesn't need a tag
    // here because the source-text scope tells it everything.
    if (isInsideDefer(tree, call_node)) return;

    // Chained deinit in a `pub fn deinit(self: *Self)` method — calling
    // `self.arena.deinit()` is part of propagating the parent's deinit.
    // Anyone holding a borrow on Self is already obligated to drop it
    // before calling Self.deinit(), so the child arena death is implicit.
    if (isInsideDeinitMethod(tree, call_node)) return;

    // Receiver text = everything before `.deinit(`.
    const receiver = text[0..deinit_paren];

    // Receiver must contain one of the arena-name hints to be in scope.
    var is_arena = false;
    for (cfg.arena_name_hints) |hint| {
        if (std.mem.indexOf(u8, receiver, hint) != null) {
            is_arena = true;
            break;
        }
    }
    if (!is_arena) return;

    // Walk back through tokens preceding `first` looking for a
    // .container_doc_comment / .doc_comment OR a regular line comment
    // (which std.zig.Ast doesn't expose as tokens — we need to scan
    // source bytes for `//`).
    if (hasKillsArenaTag(tree, first, receiver)) return;

    try report(gpa, tree, first, cfg.severity, out,
        "deinit() on arena-shaped receiver `{s}` needs a `// @kills_arena({s})` line comment immediately above",
        .{ std.mem.trim(u8, receiver, " \t\n"), std.mem.trim(u8, receiver, " \t\n") });
}

/// True when the call is inside any defer scope — either `defer <expr>;`
/// (immediate form) or `defer { ... <expr> ... }` (block form).  We walk
/// back through tokens tracking brace depth; when depth becomes negative
/// (i.e. we leave the call's containing block), check for `defer` /
/// `errdefer` immediately to the left.
fn isInsideDefer(tree: *const Ast, call_node: Ast.Node.Index) bool {
    const first = tree.firstToken(call_node);
    if (first == 0) return false;
    var brace_depth: i32 = 0;
    var t: i64 = @as(i64, @intCast(first)) - 1;
    while (t >= 0) : (t -= 1) {
        const tok: Ast.TokenIndex = @intCast(t);
        const tag = tree.tokens.items(.tag)[tok];
        switch (tag) {
            .l_brace => {
                if (brace_depth == 0) {
                    // Hit the opening brace of our containing block.
                    // Look one token left for `defer` / `errdefer`.
                    if (t == 0) return false;
                    const prev = tree.tokens.items(.tag)[@intCast(t - 1)];
                    return prev == .keyword_defer or prev == .keyword_errdefer;
                }
                brace_depth -= 1;
            },
            .r_brace => brace_depth += 1,
            .keyword_defer, .keyword_errdefer => {
                if (brace_depth == 0) return true;
            },
            // Don't treat `;` as a scope exit — sibling statements share
            // the same containing block; we want to escape to that block's
            // opening `{` and check what's before it.
            else => {},
        }
    }
    return false;
}

/// True when the call sits inside a function literally named `deinit`.
/// Walks ancestors of the call by scanning backward for `fn deinit(` —
/// good enough for the chained-deinit pattern without needing real AST
/// ancestor traversal.
fn isInsideDeinitMethod(tree: *const Ast, call_node: Ast.Node.Index) bool {
    const first = tree.firstToken(call_node);
    const call_start = tree.tokens.items(.start)[first];
    // Search backward in source for the nearest `fn deinit(` opening.
    const src = tree.source[0..call_start];
    var i: usize = src.len;
    while (i > 0) {
        i -= 1;
        if (i < 4) break;
        // Look for "fn deinit" with simple identifier boundary check.
        if (src[i] == 'f' and i + 9 <= src.len) {
            const slice = src[i .. i + 9];
            if (std.mem.eql(u8, slice, "fn deinit")) return true;
        }
    }
    return false;
}

/// Scan source bytes immediately before the call site for a line comment
/// matching `// @kills_arena(<receiver>)`.  Walks back from the call's
/// first byte through whitespace lines until a non-blank line is found.
fn hasKillsArenaTag(tree: *const Ast, first_tok: Ast.TokenIndex, receiver: []const u8) bool {
    const start = tree.tokens.items(.start)[first_tok];
    if (start == 0) return false;

    // Find the start of the current line.
    var line_start: usize = start;
    while (line_start > 0 and tree.source[line_start - 1] != '\n') line_start -= 1;
    if (line_start == 0) return false;

    // Walk backward over blank/whitespace-only lines.
    var prev_line_end: usize = line_start - 1; // the '\n' before our line
    while (prev_line_end > 0) {
        var prev_line_start = prev_line_end;
        while (prev_line_start > 0 and tree.source[prev_line_start - 1] != '\n') prev_line_start -= 1;
        const prev_line = tree.source[prev_line_start..prev_line_end];

        const trimmed = std.mem.trim(u8, prev_line, " \t\r");
        if (trimmed.len == 0) {
            // blank line — keep walking back
            if (prev_line_start == 0) return false;
            prev_line_end = prev_line_start - 1;
            continue;
        }
        // Must be a `//` line comment.
        if (!std.mem.startsWith(u8, trimmed, "//")) return false;
        var body = trimmed[2..];
        body = std.mem.trim(u8, body, " \t");

        // `@kills_arena(<name>)` — check inner name matches `receiver`.
        const prefix = "@kills_arena(";
        if (!std.mem.startsWith(u8, body, prefix)) return false;
        const after = body[prefix.len..];
        const close = std.mem.indexOfScalar(u8, after, ')') orelse return false;
        const name = std.mem.trim(u8, after[0..close], " \t");
        const recv_trimmed = std.mem.trim(u8, receiver, " \t\n");
        return std.mem.eql(u8, name, recv_trimmed);
    }
    return false;
}

fn report(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    tok: Ast.TokenIndex,
    severity: problem_mod.Severity,
    out: *std.ArrayListUnmanaged(Problem),
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const msg = try std.fmt.allocPrint(gpa, fmt, args);
    try out.append(gpa, .{
        .rule_id = RULE_ID,
        .severity = severity,
        .start = Pos.fromTokenStart(tree, tok),
        .end = Pos.fromTokenEnd(tree, tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

const Expected = struct {
    line: u32,
    substring: []const u8,
};

fn expectProblems(gpa: std.mem.Allocator, src: []const u8, expected: []const Expected) !void {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(src_z);

    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);

    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    defer {
        for (problems.items) |*p| p.deinit(gpa);
        problems.deinit(gpa);
    }

    try check(gpa, &tree, .{}, &problems);

    if (problems.items.len != expected.len) {
        std.debug.print("\nexpected {} problems, got {}:\n", .{ expected.len, problems.items.len });
        for (problems.items) |p| std.debug.print("  line {}: {s}\n", .{ p.start.line, p.message });
        return error.WrongProblemCount;
    }
    for (problems.items, expected) |p, e| {
        try std.testing.expectEqual(e.line, p.start.line);
        if (std.mem.indexOf(u8, p.message, e.substring) == null) return error.MessageMismatch;
    }
}

test "untagged arena deinit flagged" {
    const src =
        \\pub fn foo() void {
        \\    var arena = init();
        \\    arena.deinit();
        \\}
        \\fn init() u32 { return 0; }
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{
        .{ .line = 3, .substring = "needs a `// @kills_arena" },
    });
}

test "tagged arena deinit passes" {
    const src =
        \\pub fn foo() void {
        \\    var arena = init();
        \\    // @kills_arena(arena)
        \\    arena.deinit();
        \\}
        \\fn init() u32 { return 0; }
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "tagged with blank line between passes" {
    const src =
        \\pub fn foo() void {
        \\    var arena = init();
        \\    // @kills_arena(arena)
        \\
        \\    arena.deinit();
        \\}
        \\fn init() u32 { return 0; }
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "non-arena deinit ignored" {
    const src =
        \\pub fn foo() void {
        \\    var list = init();
        \\    list.deinit();
        \\}
        \\fn init() u32 { return 0; }
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "wrong-target tag flagged" {
    const src =
        \\pub fn foo() void {
        \\    var arena = init();
        \\    // @kills_arena(other)
        \\    arena.deinit();
        \\}
        \\fn init() u32 { return 0; }
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{
        .{ .line = 4, .substring = "needs a `// @kills_arena" },
    });
}

test "defer-bound arena deinit exempt — scope-exit is implicit" {
    const src =
        \\pub fn foo() void {
        \\    var arena = init();
        \\    defer arena.deinit();
        \\    bar();
        \\}
        \\fn init() u32 { return 0; }
        \\fn bar() void {}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "errdefer-bound arena deinit exempt" {
    const src =
        \\pub fn foo() !void {
        \\    var arena = init();
        \\    errdefer arena.deinit();
        \\    try bar();
        \\}
        \\fn init() u32 { return 0; }
        \\fn bar() !void {}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "defer-block with multiple deinits exempt" {
    const src =
        \\pub fn foo() void {
        \\    var a = init();
        \\    var b = init();
        \\    defer {
        \\        a.arena.deinit();
        \\        b.arena.deinit();
        \\    }
        \\    work();
        \\}
        \\fn init() u32 { return 0; }
        \\fn work() void {}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "chained deinit inside deinit() method exempt" {
    const src =
        \\const Self = struct {
        \\    arena: u32,
        \\    pub fn deinit(self: *Self) void {
        \\        self.arena.deinit();
        \\    }
        \\};
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}

test "dotted receiver matches dotted tag" {
    const src =
        \\pub fn foo(self: anytype) void {
        \\    // @kills_arena(self.arena)
        \\    self.arena.deinit();
        \\}
        \\
    ;
    try expectProblems(std.testing.allocator, src, &.{});
}
