//! Memset-undef-after-len-truncation detector — `self.items.len =
//! NEW; @memset(self.items[NEW..], undefined);` (or `= 0; @memset(
//! self.items, undefined)`) — the memset slices the ALREADY-
//! TRUNCATED items, so the range is empty and the memset is a no-op.
//! The freed-but-retained capacity keeps its old bytes, defeating
//! Zig's `undefined` use-after-shrink safety detection.
//!
//! Real-world: ziglang/zig#25810 + #25832 fix this in both
//! `ArrayListAligned` and `ArrayListAlignedManaged`'s
//! `shrinkRetainingCapacity` / `clearRetainingCapacity`.

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("../lexer.zig");
const scope = @import("../scope.zig");
const problem = @import("../problem.zig");
const testing = @import("../testing.zig");
const config_mod = @import("../config.zig");

const TokenIndex = lexer.TokenIndex;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(problem.Problem),
) !void {
    if (!config_mod.isEnabled(config, .memset_undef_after_len_truncation)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = lexer.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        try checkBody(gpa, tree, fn_entry.body, problems);
    }
}

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(problem.Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var walk = scope.BodyWalk.init(tags, first, last);
    while (walk.t + 5 <= last) : (walk.t += 1) {
        if (walk.atNestedFn()) {
            walk.skipNestedFn();
            continue;
        }
        // Pattern: `<X>.<field>.len = ...`
        const t = walk.t;
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .period) continue;
        if (tags[t + 4] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 4), "len")) continue;
        if (t + 5 > last or tags[t + 5] != .equal) continue;
        const x_name = tree.tokenSlice(t);
        const field_name = tree.tokenSlice(t + 2);
        const sc = lexer.findStmtSemicolon(tags, t + 6, last) orelse continue;
        const memset_tok = findMemsetOnSlice(tree, sc + 1, last, x_name, field_name) orelse {
            walk.t = sc;
            continue;
        };
        try report(gpa, problems, tree, memset_tok, x_name, field_name);
        walk.t = sc;
    }
}

/// `@memset(<X>.<field>...)` where the first arg starts with the
/// target slice.
fn findMemsetOnSlice(
    tree: *const Ast,
    start: TokenIndex,
    last: TokenIndex,
    x_name: []const u8,
    field_name: []const u8,
) ?TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var t: TokenIndex = start;
    while (t + 4 <= last) : (t += 1) {
        if (tags[t] == .r_brace) return null;
        if (tags[t] != .builtin) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "@memset")) continue;
        if (tags[t + 1] != .l_paren) continue;
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), x_name)) continue;
        if (tags[t + 3] != .period) continue;
        if (tags[t + 4] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 4), field_name)) continue;
        return t;
    }
    return null;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(problem.Problem),
    tree: *const Ast,
    memset_tok: TokenIndex,
    x_name: []const u8,
    field_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`@memset({s}.{s}[...]...)` follows `{s}.{s}.len = ...;` — the memset slices the ALREADY-TRUNCATED items so the range is empty and the memset is a no-op.  The freed-but-retained capacity keeps its old bytes, defeating Zig's `undefined` use-after-shrink safety.  Swap the order: `@memset(...)` BEFORE the `.len = ...` truncation",
        .{ x_name, field_name, x_name, field_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "memset-undef-after-len-truncation",
        .severity = .@"error",
        .start = problem.Pos.fromTokenStart(tree, memset_tok),
        .end = problem.Pos.fromTokenEnd(tree, memset_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

const R = "memset-undef-after-len-truncation";

test "shrink-then-memset (canonical bug) fires" {
    try testing.expectFires(check, R,
        \\const T = struct {
        \\    items: []u8,
        \\    pub fn shrink(self: *T, new_len: usize) void {
        \\        self.items.len = new_len;
        \\        @memset(self.items[new_len..], undefined);
        \\    }
        \\};
    );
}

test "clear-then-memset-all (clearRetainingCapacity bug) fires" {
    try testing.expectFires(check, R,
        \\const T = struct {
        \\    items: []u8,
        \\    pub fn clear(self: *T) void {
        \\        self.items.len = 0;
        \\        @memset(self.items, undefined);
        \\    }
        \\};
    );
}

test "memset BEFORE truncation (correct order) doesn't fire" {
    try testing.expectNoFire(check,
        \\const T = struct {
        \\    items: []u8,
        \\    pub fn shrinkFixed(self: *T, new_len: usize) void {
        \\        @memset(self.items[new_len..], undefined);
        \\        self.items.len = new_len;
        \\    }
        \\};
    );
}

test "memset on a different field doesn't fire" {
    try testing.expectNoFire(check,
        \\const T = struct {
        \\    items: []u8,
        \\    other: []u8,
        \\    pub fn shrink(self: *T, new_len: usize) void {
        \\        self.items.len = new_len;
        \\        @memset(self.other, undefined);
        \\    }
        \\};
    );
}
