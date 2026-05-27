//! Detects `@alignCast(x.?)` — combining a forced optional unwrap with an
//! alignment assertion inside the same `@alignCast` call.  If `x` is null the
//! forced `.?` panics; if non-null the subsequent alignment check may also
//! panic on unaligned input.  The correct form is to use a non-optional type
//! for the pointer, or to guard with `orelse` before casting.
//!
//! Real-world instance:
//!   - tigerbeetle/tigerbeetle#3717 (io: even_listen):
//!     `@ptrCast(@alignCast(ctx.?))` — the nullable context was forced-unwrapped
//!     inside the align-cast; both the null-deref and the misalign checks were
//!     implicit.  Fix: changed all `?*anyopaque` context parameters to
//!     `*anyopaque`, eliminating the `.?` at every dereference site.
//!
//! Detection (Tier 1, flat token walk):
//!   Pattern: `builtin("@alignCast") l_paren identifier period question_mark r_paren`
//!   — 6 tokens.  Fire at the `@alignCast` builtin token.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");
const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "aligncast-on-optional-unwrap";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .aligncast_on_optional_unwrap)) return;
    _ = cache;

    const tags = tree.tokens.items(.tag);
    const last_tok: Ast.TokenIndex = @intCast(tree.tokens.len -| 1);

    var t: Ast.TokenIndex = 0;
    while (t + 5 <= last_tok) : (t += 1) {
        // Pattern: @alignCast ( identifier . ? )
        if (tags[t] != .builtin) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), "@alignCast")) continue;
        if (tags[t + 1] != .l_paren) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .period) continue;
        if (tags[t + 4] != .question_mark) continue;
        if (tags[t + 5] != .r_paren) continue;

        try report(gpa, problems, tree, t);
    }
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    aligncast_tok: Ast.TokenIndex,
) !void {
    const name = tree.tokenSlice(aligncast_tok + 2);
    const msg = try std.fmt.allocPrint(
        gpa,
        "`@alignCast({s}.?)` — the forced `.?` panics when `{s}` is null and the alignment assertion may also panic on unaligned data; use a non-optional type for the pointer, or guard with `orelse` before casting",
        .{ name, name },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, aligncast_tok),
        .end = Pos.fromTokenEnd(tree, aligncast_tok + 5),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "aligncast-on-optional-unwrap: fires on @alignCast(x.?)" {
    try testing.expectFires(check, R,
        \\fn dispatchCallback(ctx: ?*anyopaque) void {
        \\    const self: *Handler = @ptrCast(@alignCast(ctx.?));
        \\    self.handle();
        \\}
        \\
    );
}

test "aligncast-on-optional-unwrap: non-optional does not fire" {
    try testing.expectNoFire(check,
        \\fn dispatchCallback(ctx: *anyopaque) void {
        \\    const self: *Handler = @ptrCast(@alignCast(ctx));
        \\    self.handle();
        \\}
        \\
    );
}

test "aligncast-on-optional-unwrap: orelse guard does not fire" {
    try testing.expectNoFire(check,
        \\fn dispatchCallback(ctx: ?*anyopaque) void {
        \\    const self: *Handler = @ptrCast(@alignCast(ctx orelse return));
        \\    self.handle();
        \\}
        \\
    );
}

test "aligncast-on-optional-unwrap: standalone .? not in alignCast does not fire" {
    try testing.expectNoFire(check,
        \\fn getHandler(opt: ?*Handler) *Handler {
        \\    return opt.?;
        \\}
        \\
    );
}
