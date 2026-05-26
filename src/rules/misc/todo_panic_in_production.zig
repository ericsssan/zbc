//! `@panic("TODO ...")` / `@panic("unimplemented")` /
//! `@panic("FIXME ...")` / `@panic("WIP ...")` left in code
//! that may run in release builds.  TODO-panics are a
//! development scaffold: harmless during prototyping but
//! escalate to runtime crashes if the path is reached in
//! production.
//!
//! Real-world: bun and other large Zig codebases periodically
//! ship TODO-panics that crash users when the placeholder
//! branch is hit.  CI catches some via tests; many slip
//! through.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Walk for `@panic(` builtin calls.
//!   2. Inspect the first argument's string literal.
//!   3. Match prefix patterns:
//!        TODO / FIXME / XXX / HACK / WIP
//!        "unimplemented" / "not implemented"
//!        "not yet" / "stub"
//!   4. Fire on the `@panic` call site.
//!
//! Distinct from `unreachable`: that's the canonical Zig
//! "this branch can't be reached" marker.  Most `unreachable`
//! sites are intentional (after exhaustive switch arms, after
//! proven-non-null unwraps).  Distinguishing
//! intentional-vs-TODO `unreachable` would need flow
//! analysis, so this rule targets only the `@panic(<msg>)`
//! form where the author wrote a clear human signal.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");

const tokens = @import("../../ast/tokens.zig");
const testing = @import("../../testing.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

const skipNestedFn = tokens.skipNestedFn;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .todo_panic_in_production)) return;
    _ = cache;
    try tokens.forEachFnBody(gpa, tree, problems, checkBody);
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

    // Track comptime-guarded brace levels.  When an `if (comptime ...)`
    // or `if (Environment.isXxx)` block opens, the `@panic` inside is
    // dead code on platforms where the condition is false — suppress it.
    // The same logic extends through `} else {` chains: once a chain of
    // comptime-guarded branches starts, even the bare `else { }` at the
    // end is transitively dead on the platforms where earlier branches
    // fire.
    //
    // Stack: brace_is_suppressed[d] = true iff the brace at depth d was
    // opened by a comptime-guarded condition.  A @panic is suppressed
    // when ANY ancestor depth is suppressed.
    const MAX_DEPTH = 64;
    var brace_is_suppressed: [MAX_DEPTH]bool = undefined;
    @memset(&brace_is_suppressed, false);
    var brace_depth: u8 = 0;
    var pending_suppress: bool = false; // next `{` opens a suppressed block
    var last_closed_was_suppressed: bool = false; // last `}` closed a suppressed block

    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }

        switch (tags[t]) {
            .keyword_if => {
                // `if (comptime ...)` — explicit comptime keyword in condition.
                if (t + 2 <= last and tags[t + 1] == .l_paren and
                    tags[t + 2] == .keyword_comptime)
                {
                    pending_suppress = true;
                } else if (t + 1 <= last and tags[t + 1] == .l_paren) {
                    // `if (Environment.isXxx)` / `if (Environment.isDebug)` —
                    // bun-style comptime platform/build flag.  Check the
                    // balanced condition for a known compile-time identifier.
                    if (ifCondIsComptimeFlag(tree, tags, t + 1, last)) {
                        pending_suppress = true;
                    }
                }
                last_closed_was_suppressed = false;
            },
            .keyword_else => {
                // `} else {` or `} else if (comptime ...) {` after a suppressed
                // block — the else/else-if is transitively dead on the platforms
                // where the prior branch was taken.  Propagate suppression into
                // the next block, BUT not for `else switch (...)`: the switch
                // arms are independent dispatch and can be individually live even
                // when the preceding if-branch was comptime-guarded.
                if (last_closed_was_suppressed and
                    (t + 1 > last or tags[t + 1] != .keyword_switch))
                {
                    pending_suppress = true;
                }
                last_closed_was_suppressed = false;
            },
            .l_brace => {
                if (brace_depth < MAX_DEPTH) {
                    brace_is_suppressed[brace_depth] = pending_suppress;
                }
                brace_depth +|= 1;
                pending_suppress = false;
                last_closed_was_suppressed = false;
            },
            .r_brace => {
                if (brace_depth > 0) {
                    brace_depth -= 1;
                    last_closed_was_suppressed = brace_is_suppressed[brace_depth];
                    brace_is_suppressed[brace_depth] = false;
                } else {
                    last_closed_was_suppressed = false;
                }
                pending_suppress = false;
            },
            .builtin => {
                if (!std.mem.eql(u8, tree.tokenSlice(t), "@panic")) continue;
                if (tags[t + 1] != .l_paren) continue;
                if (tags[t + 2] != .string_literal) continue;
                // Skip if inside any comptime-guarded brace level.
                const depth = @min(brace_depth, MAX_DEPTH);
                var suppressed = false;
                for (brace_is_suppressed[0..depth]) |s| {
                    if (s) { suppressed = true; break; }
                }
                if (suppressed) continue;
                // Strip surrounding quotes.
                const lit = tree.tokenSlice(t + 2);
                if (lit.len < 2) continue;
                const inner = lit[1 .. lit.len - 1];
                if (!isTodoMessage(inner)) continue;
                try report(gpa, problems, tree, t, inner);
            },
            else => {
                last_closed_was_suppressed = false;
            },
        }
    }
}

/// True iff the `if` condition starting at `lparen` (the `(` token)
/// looks like a compile-time-known flag expression, e.g.:
///   `Environment.isWindows` / `Environment.isDebug` /
///   `builtin.os.tag == .windows`
/// Conservative: only matches the simple `<ident>.<ident>` shape (no
/// `!`, `and`, `or`) where the RHS identifier is a known compile-time
/// flag name.
fn ifCondIsComptimeFlag(
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    lparen: Ast.TokenIndex,
    last: Ast.TokenIndex,
) bool {
    // Walk the balanced condition looking for `<ident> . <comptime-flag>`.
    var t = lparen + 1;
    var depth: i32 = 1;
    while (t <= last and depth > 0) : (t += 1) {
        switch (tags[t]) {
            .l_paren => depth += 1,
            .r_paren => {
                depth -= 1;
                if (depth == 0) break;
            },
            .period => {
                // Check the identifier that follows this `.`.
                if (t + 1 <= last and tags[t + 1] == .identifier) {
                    const name = tree.tokenSlice(t + 1);
                    if (isComptimeFlagName(name)) return true;
                }
            },
            else => {},
        }
    }
    return false;
}

/// Known compile-time boolean flag names used as `if (Env.X)` guards.
/// Covers bun's `Environment` fields and common Zig stdlib patterns.
fn isComptimeFlagName(name: []const u8) bool {
    const known = [_][]const u8{
        "isWindows", "isLinux",  "isMac",     "isPosix",
        "isKqueue",  "isBSD",    "isDebug",   "isRelease",
        "allow_assert",          "isNative",
    };
    for (known) |k| {
        if (std.mem.eql(u8, name, k)) return true;
    }
    return false;
}

/// True iff the panic message looks like a TODO marker.
/// Case-insensitive prefix matching for common signals.
fn isTodoMessage(msg: []const u8) bool {
    if (startsWithIgnoreCase(msg, "todo")) return true;
    if (startsWithIgnoreCase(msg, "fixme")) return true;
    if (startsWithIgnoreCase(msg, "xxx")) return true;
    if (startsWithIgnoreCase(msg, "hack")) return true;
    if (startsWithIgnoreCase(msg, "wip")) return true;
    if (startsWithIgnoreCase(msg, "unimplemented")) return true;
    if (startsWithIgnoreCase(msg, "not implemented")) return true;
    if (startsWithIgnoreCase(msg, "not yet")) return true;
    if (startsWithIgnoreCase(msg, "stub")) return true;
    if (containsIgnoreCase(msg, "TODO")) return true;
    return false;
}

fn startsWithIgnoreCase(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    for (prefix, 0..) |pc, i| {
        if (asciiToLower(s[i]) != asciiToLower(pc)) return false;
    }
    return true;
}

fn containsIgnoreCase(s: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > s.len) return false;
    var i: usize = 0;
    while (i + needle.len <= s.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            if (asciiToLower(s[i + j]) != asciiToLower(nc)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

fn asciiToLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + ('a' - 'A');
    return c;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    panic_tok: Ast.TokenIndex,
    msg_text: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`@panic(\"{s}\")` is a TODO/unimplemented marker — if this branch is reached in a release build it crashes the user's process.  Either return an explicit error (`return error.NotYetImplemented;` if the fn is in an error-union return shape) or ensure the branch is unreachable by construction (gate at compile time with `comptime` checks / static dispatch)",
        .{msg_text},
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = "todo-panic-in-production",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, panic_tok),
        .end = Pos.fromTokenEnd(tree, panic_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────────

const freeProblems = testing.freeProblems;

test "todo-panic-in-production: @panic(\"TODO\") fires" {
    const gpa = std.testing.allocator;
    var problems = try testing.runRule(gpa, check,
        \\pub fn foo() void {
        \\    @panic("TODO: implement this");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("todo-panic-in-production", problems.items[0].rule_id);
}

test "todo-panic-in-production: @panic(\"unimplemented\") fires" {
    const gpa = std.testing.allocator;
    var problems = try testing.runRule(gpa, check,
        \\pub fn foo() void {
        \\    @panic("unimplemented");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "todo-panic-in-production: @panic(\"FIXME ...\") fires" {
    const gpa = std.testing.allocator;
    var problems = try testing.runRule(gpa, check,
        \\pub fn foo() void {
        \\    @panic("FIXME: handle the edge case");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "todo-panic-in-production: regular @panic does NOT fire" {
    const gpa = std.testing.allocator;
    var problems = try testing.runRule(gpa, check,
        \\pub fn foo() void {
        \\    @panic("internal assertion failure");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "todo-panic-in-production: unreachable does NOT fire" {
    const gpa = std.testing.allocator;
    var problems = try testing.runRule(gpa, check,
        \\pub fn foo(x: u8) u8 {
        \\    return switch (x) {
        \\        0 => 1,
        \\        1 => 2,
        \\        else => unreachable,
        \\    };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "todo-panic-in-production: case-insensitive TODO inside message fires" {
    const gpa = std.testing.allocator;
    var problems = try testing.runRule(gpa, check,
        \\pub fn foo() void {
        \\    @panic("internal: todo handle this");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "todo-panic-in-production: if (comptime cond) { @panic } does NOT fire" {
    // Pattern: bun.zig:639 `if (comptime Environment.isWindows) { @panic("TODO on Windows"); }`
    // The block is dead code on non-Windows; no production crash possible.
    try testing.expectNoFire(check,
        \\const Env = struct { pub const isWindows: bool = false; };
        \\pub fn foo() void {
        \\    if (comptime Env.isWindows) {
        \\        @panic("TODO on Windows");
        \\    }
        \\}
    );
}

test "todo-panic-in-production: if (Environment.isDebug) { @panic } does NOT fire" {
    // Pattern: sys/Error.zig:318 `if (Environment.isDebug) { @panic("Error.todo() was called"); }`
    // Debug-only guard — never fires in a release build.
    try testing.expectNoFire(check,
        \\const Environment = struct { pub const isDebug: bool = false; };
        \\pub fn todo() void {
        \\    if (Environment.isDebug) {
        \\        @panic("TODO: debug sentinel");
        \\    }
        \\}
    );
}

test "todo-panic-in-production: if (Environment.isWindows) { @panic } does NOT fire" {
    // Pattern: OutputFile.zig:308 — `Environment.isWindows` is a comptime constant.
    try testing.expectNoFire(check,
        \\const Environment = struct { pub const isWindows: bool = false; };
        \\pub fn foo() void {
        \\    if (Environment.isWindows) {
        \\        @panic("TODO windows");
        \\    }
        \\}
    );
}

test "todo-panic-in-production: comptime if-else chain, bare else @panic — does NOT fire" {
    // Pattern: io/io.zig:106 — `} else { @panic("TODO on this platform") }`
    // following a chain of `if (comptime isLinux) / else if (comptime isKqueue)`.
    // On Linux/macOS the else is dead code (transitively suppressed).
    try testing.expectNoFire(check,
        \\const E = struct {
        \\    pub const isLinux: bool = true;
        \\    pub const isKqueue: bool = false;
        \\};
        \\pub fn tick() void {
        \\    if (comptime E.isLinux) {
        \\        _ = 1;
        \\    } else if (comptime E.isKqueue) {
        \\        _ = 2;
        \\    } else {
        \\        @panic("TODO on this platform");
        \\    }
        \\}
    );
}

test "todo-panic-in-production: else-switch arm after comptime-if still fires" {
    // Pattern: Cmd.zig:594 — `if (comptime in_cmd_subst) { ... } else switch (x) { ... @panic }`
    // The else-switch is the live branch (in_cmd_subst = false), so the panic IS reachable.
    try testing.expectFires(check, "todo-panic-in-production",
        \\pub fn foo(x: u8) void {
        \\    const in_cmd_subst = false;
        \\    if (comptime in_cmd_subst) {
        \\        _ = x;
        \\    } else switch (x) {
        \\        0 => {},
        \\        else => @panic("TODO handle other cases"),
        \\    }
        \\}
    );
}

test "todo-panic-in-production: @panic after comptime-if (not inside it) still fires" {
    // Pattern: bun.zig:1315 — panic is OUTSIDE the comptime block (at fn scope),
    // not inside it.  On non-Windows the panic IS reachable.
    try testing.expectFires(check, "todo-panic-in-production",
        \\const Env = struct { pub const isWindows: bool = false; };
        \\pub fn getFdPathW() void {
        \\    if (comptime Env.isWindows) {
        \\        return;
        \\    }
        \\    @panic("TODO unsupported platform");
        \\}
    );
}
