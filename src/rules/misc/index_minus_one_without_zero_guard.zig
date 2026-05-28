//! Detects array subscript expressions of the form `buf[idx - 1]` where the
//! `idx - 1` subtraction is not guarded against `idx == 0`.  When `idx` is
//! `usize` and equals zero, `idx - 1` wraps to `maxInt(usize)` —
//! an OOB trap in Debug/Safe and a silent arbitrary-memory read in
//! ReleaseFast.
//!
//! Real-world instances:
//!   - oven-sh/bun#24561 (hosted_git_info.zig): `npa_str[pi - 1]` where `pi`
//!     optional payload could be 0; fix added `pi == 0 or` guard.
//!   - oven-sh/bun#28487 (braces.zig): `self.items[self.current - 1]` when
//!     `self.current` could be 0; fix added `if (self.current > 0)` guard.
//!   - ziglang/zig#26057 (ArgIteratorWasi): `self.args[self.args.len - 1]`
//!     panics when `self.args.len == 0`; `0 - 1` wraps to `maxInt(usize)`.
//!
//! Detection (Tier 1, token walk):
//!   Form A: `[ identifier - 1 ]`                          (5 tokens)
//!   Form B: `[ identifier . identifier - 1 ]`             (7 tokens)
//!   Form C: `[ identifier . identifier . len - 1 ]`       (9 tokens)
//!   Fire at the `l_bracket` token.
//!
//! Suppression (six checks, all applied):
//!
//!   1. Same-expression `and`-guard (window 15): `GUARD_IDENT (> | !=) 0
//!      keyword_and` immediately before the array identifier.
//!      Covers `x > 0 and buf[x - 1]`.
//!
//!   2. If/for-body guard (AST pre-pass, `collectGuardedRanges`):
//!      Scans `if_simple`/`if` nodes via `tree.fullIf`:
//!      • `IDENT (> | !=) 0` in condition → records `then_expr` range.
//!      • `IDENT == 0` in condition → records `else_expr` range.
//!      Scans `for_simple`/`for` nodes via `tree.fullFor`:
//!      • Single input `K..N` with K ≥ 1 → capture ≥ 1, records body range.
//!        Covers `for (1..n) |i| arr[i-1]` and `for (2..n) |i| arr[i-1]`.
//!      • Single input is a literal array with all values > 0 → capture > 0.
//!        Covers `inline for ([_]usize{7,6,5,4,3,2,1}) |i| arr[i-1]`.
//!      Token-range containment is exact for all body shapes.
//!
//!   3. Assert guard (window 50): scans inside `assert(...)` for
//!      `GUARD_IDENT (> | !=) 0` (simple or dotted), including compound
//!      conditions (`assert(a > 0 and b.len > 0)`) and OR-short-circuit
//!      forms (`assert(x == 0 or arr[x-1] < limit)`).
//!
//!   4. Early-exit guard (window 45): `if (GUARD == 0)` followed within 3
//!      tokens by `return`, `continue`, or `break`.  Covers
//!      `if (i == 0) continue; arr[i - 1]` in loop bodies.
//!
//!   5. Comptime context (window 5): `keyword_comptime` within 5 tokens of `[`.
//!      A comptime subscript is bounds-checked at compile time.
//!      Covers `comptime assert(fmt[fmt.len - 1] == '\n')`.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../../problem.zig");
const config_mod = @import("../../config.zig");
const file_cache_mod = @import("../../cache/file_cache.zig");

const tokens = @import("../../ast/tokens.zig");
const testing = @import("../../testing.zig");

const skipNestedFn = tokens.skipNestedFn;

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "index-minus-one-without-zero-guard";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .index_minus_one_without_zero_guard)) return;
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

    if (first + 4 > last) return;

    // AST pre-pass: collect token ranges of if-bodies whose condition
    // contains a zero-guard on some identifier.  Used by `isInGuardedRange`.
    var guarded = try collectGuardedRanges(gpa, tree, first, last);
    defer guarded.deinit(gpa);

    var t: Ast.TokenIndex = first;
    while (t + 4 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }

        if (tags[t] != .l_bracket) continue;

        // Subscript inside a `comptime` expression is evaluated at compile
        // time; any OOB would be a compile error, not a runtime panic.
        if (hasComptimeContext(tags, t)) continue;

        // Form A: `[ identifier - 1 ]`
        //   t+0: l_bracket
        //   t+1: identifier
        //   t+2: minus
        //   t+3: number_literal "1"
        //   t+4: r_bracket
        if (tags[t + 1] == .identifier and
            tags[t + 2] == .minus and
            tags[t + 3] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(t + 3), "1") and
            tags[t + 4] == .r_bracket)
        {
            const idx_name = tree.tokenSlice(t + 1);
            if (hasAndGuard(tags, tree, t, &.{idx_name})) continue;
            if (isInGuardedRange(guarded.items, t, &.{idx_name})) continue;
            if (hasAssertGuard(tags, tree, t, &.{idx_name})) continue;
            if (hasEarlyReturnGuard(tags, tree, t, &.{idx_name})) continue;
            if (hasIncrementGuard(tags, tree, t, &.{idx_name})) continue;
            if (hasInitToOneGuard(tags, tree, t, &.{idx_name})) continue;
            try report(gpa, problems, tree, t, idx_name);
            continue;
        }

        // Form B: `[ identifier . identifier - 1 ]`
        //   t+0: l_bracket
        //   t+1: identifier
        //   t+2: period
        //   t+3: identifier
        //   t+4: minus
        //   t+5: number_literal "1"
        //   t+6: r_bracket
        if (t + 6 <= last and
            tags[t + 1] == .identifier and
            tags[t + 2] == .period and
            tags[t + 3] == .identifier and
            tags[t + 4] == .minus and
            tags[t + 5] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(t + 5), "1") and
            tags[t + 6] == .r_bracket)
        {
            const outer_name = tree.tokenSlice(t + 1);
            const idx_name = tree.tokenSlice(t + 3);
            // `constants.X` is a comptime namespace in Zig; subscripts are safe.
            if (std.mem.eql(u8, outer_name, "constants")) continue;
            if (hasAndGuard(tags, tree, t, &.{ outer_name, idx_name })) continue;
            if (isInGuardedRange(guarded.items, t, &.{ outer_name, idx_name })) continue;
            if (hasAssertGuard(tags, tree, t, &.{ outer_name, idx_name })) continue;
            if (hasEarlyReturnGuard(tags, tree, t, &.{ outer_name, idx_name })) continue;
            if (hasZeroAccessGuard(tags, tree, t, &.{ outer_name, idx_name })) continue;
            if (hasIncrementGuard(tags, tree, t, &.{ outer_name, idx_name })) continue;
            if (hasInitToOneGuard(tags, tree, t, &.{ outer_name, idx_name })) continue;
            try report(gpa, problems, tree, t, idx_name);
            continue;
        }

        // Form C: `[ identifier . identifier . len - 1 ]`
        //   t+0: l_bracket
        //   t+1: identifier (recv)
        //   t+2: period
        //   t+3: identifier (field)
        //   t+4: period
        //   t+5: identifier "len"
        //   t+6: minus
        //   t+7: number_literal "1"
        //   t+8: r_bracket
        if (t + 8 <= last and
            tags[t + 1] == .identifier and
            tags[t + 2] == .period and
            tags[t + 3] == .identifier and
            tags[t + 4] == .period and
            tags[t + 5] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t + 5), "len") and
            tags[t + 6] == .minus and
            tags[t + 7] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(t + 7), "1") and
            tags[t + 8] == .r_bracket)
        {
            const recv_name = tree.tokenSlice(t + 1);
            const field_name = tree.tokenSlice(t + 3);
            if (std.mem.eql(u8, recv_name, "constants")) continue;
            if (hasAndGuard(tags, tree, t, &.{ recv_name, field_name, "len" })) continue;
            if (isInGuardedRange(guarded.items, t, &.{ recv_name, field_name, "len" })) continue;
            if (hasAssertGuard(tags, tree, t, &.{ recv_name, field_name, "len" })) continue;
            if (hasEarlyReturnGuard(tags, tree, t, &.{ recv_name, field_name, "len" })) continue;
            if (hasZeroAccessGuard(tags, tree, t, &.{ recv_name, field_name })) continue;
            try reportC(gpa, problems, tree, t, recv_name, field_name);
            continue;
        }
    }
}

/// True when `keyword_comptime` appears within 5 tokens before `[`.
/// A subscript evaluated at compile time cannot cause a runtime OOB panic.
fn hasComptimeContext(tags: []const std.zig.Token.Tag, t: Ast.TokenIndex) bool {
    const window: u32 = 5;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] == .keyword_comptime) return true;
    }
    return false;
}

/// Returns true when a same-expression `and`-guard for one of `guard_names` is
/// present in the 15 tokens immediately before the `[` at position `t`.
///
/// Matched token pattern (reading backward from `t`):
///   ... GUARD_IDENT (> | !=) 0 keyword_and ARRAY_IDENT [t]
///
/// GUARD_IDENT must match one of `guard_names`.  Covers `x > 0 and buf[x - 1]`
/// and `prefix.len > 0 and arr[prefix.len - 1]` (guard_names includes both
/// "prefix" and "len" for Form B).
fn hasAndGuard(
    tags: []const std.zig.Token.Tag,
    tree: *const Ast,
    t: Ast.TokenIndex,
    guard_names: []const []const u8,
) bool {
    if (t < 5) return false;
    const window: u32 = 15;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] != .keyword_and) continue;
        if (k < 3) continue;
        if (tags[k - 1] != .number_literal) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(k - 1), "0")) continue;
        if (tags[k - 2] != .angle_bracket_right and tags[k - 2] != .bang_equal) continue;
        if (tags[k - 3] != .identifier) continue;
        const guard_id = tree.tokenSlice(k - 3);
        for (guard_names) |gn| {
            if (std.mem.eql(u8, guard_id, gn)) return true;
        }
    }
    return false;
}

/// One entry from the AST pre-pass: guard identifiers + the EXACT token range
/// of the corresponding if-body (`then_expr`).  A subscript `[` that falls
/// within [first, last] is structurally inside the if-body.
const GuardedRange = struct {
    names: [3][]const u8,
    n: u8,
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
};

/// Walk all AST nodes in [body_first, body_last].
///
/// `if_simple`/`if` nodes:
///   • Condition `IDENT (> | !=) 0` → record `then_expr` range.
///   • Condition `IDENT == 0`       → record `else_expr` range.
///
/// `for_simple`/`for` nodes with a single iterable:
///   • Iterable is a range `K..N` with K ≥ 1 (e.g. `1..len`, `2..max+1`):
///     the capture variable is guaranteed ≥ 1 inside the body.
///   • Iterable is a literal array `{v1, v2, …}` where all vᵢ > 0
///     (e.g. `inline for ([_]usize{7,6,5,4,3,2,1}) |i|`):
///     the capture variable takes only positive values.
///
/// In both `for` cases the exact token range of `then_expr` (the loop body)
/// is recorded as a guarded range for the capture variable name.
fn collectGuardedRanges(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body_first: Ast.TokenIndex,
    body_last: Ast.TokenIndex,
) !std.ArrayListUnmanaged(GuardedRange) {
    var out: std.ArrayListUnmanaged(GuardedRange) = .empty;
    const ttags = tree.tokens.items(.tag);
    const ntags = tree.nodes.items(.tag);

    var ni: u32 = 1;
    while (ni < tree.nodes.len) : (ni += 1) {
        const node: Ast.Node.Index = @enumFromInt(ni);
        const ntag = ntags[ni];

        const nf = tree.firstToken(node);
        const nl = tree.lastToken(node);
        if (nf < body_first or nl > body_last) continue;

        // ── For-loop analysis ─────────────────────────────────────────────
        if (ntag == .for_simple or ntag == .@"for") {
            const fd = tree.fullFor(node) orelse continue;
            // Only handle single-iterable for-loops.
            if (fd.ast.inputs.len != 1) continue;
            const input = fd.ast.inputs[0];

            // payload_token points directly to the first capture identifier
            // (not the preceding `|`).  Skip `*` for pointer captures.
            var pt = fd.payload_token;
            if (pt < tree.tokens.len and ttags[pt] == .asterisk) pt += 1;
            if (pt >= tree.tokens.len or ttags[pt] != .identifier) continue;
            const capture = tree.tokenSlice(pt);

            const input_first = tree.firstToken(input);
            var guarded = false;

            // Case A: range `K..N` where K ≥ 1 (integer literal).
            //   Capture iterates K, K+1, …, N-1 — all ≥ 1.
            if (ttags[input_first] == .number_literal and
                input_first + 1 < tree.tokens.len and
                ttags[input_first + 1] == .ellipsis2)
            {
                const start_val = std.fmt.parseUnsigned(u64, tree.tokenSlice(input_first), 0) catch 0;
                if (start_val >= 1) guarded = true;
            }

            // Case B: literal array `{v1, v2, …}` with all vᵢ > 0.
            if (!guarded) guarded = isAllPositiveLiterals(tree, ttags, input);

            if (guarded) {
                try out.append(gpa, .{
                    .names = .{ capture, "", "" },
                    .n = 1,
                    .first = tree.firstToken(fd.ast.then_expr),
                    .last = tree.lastToken(fd.ast.then_expr),
                });
            }
            continue;
        }

        // ── If-node analysis ──────────────────────────────────────────────
        if (ntag != .if_simple and ntag != .@"if") continue;

        const ifd = tree.fullIf(node) orelse continue;
        const cf = tree.firstToken(ifd.ast.cond_expr);
        const cl = tree.lastToken(ifd.ast.cond_expr);

        var nonzero_names: [3][]const u8 = .{ "", "", "" };
        var nz: u8 = 0;
        var zero_names: [3][]const u8 = .{ "", "", "" };
        var zn: u8 = 0;

        var ct = cf;
        while (ct <= cl) : (ct += 1) {
            if (ttags[ct] != .identifier) continue;
            // Dotted: OUTER . INNER cmp 0
            if (ct + 4 <= cl and
                ttags[ct + 1] == .period and
                ttags[ct + 2] == .identifier and
                ttags[ct + 4] == .number_literal and
                std.mem.eql(u8, tree.tokenSlice(ct + 4), "0"))
            {
                const cmp = ttags[ct + 3];
                if ((cmp == .angle_bracket_right or cmp == .bang_equal) and nz + 1 < 3) {
                    nonzero_names[nz] = tree.tokenSlice(ct);
                    nonzero_names[nz + 1] = tree.tokenSlice(ct + 2);
                    nz += 2;
                } else if (cmp == .equal_equal and zn + 1 < 3) {
                    zero_names[zn] = tree.tokenSlice(ct);
                    zero_names[zn + 1] = tree.tokenSlice(ct + 2);
                    zn += 2;
                }
                ct += 4;
                continue;
            }
            // Simple: IDENT cmp 0
            if (ct + 2 <= cl and
                ttags[ct + 2] == .number_literal and
                std.mem.eql(u8, tree.tokenSlice(ct + 2), "0"))
            {
                const cmp = ttags[ct + 1];
                if ((cmp == .angle_bracket_right or cmp == .bang_equal) and nz < 3) {
                    nonzero_names[nz] = tree.tokenSlice(ct);
                    nz += 1;
                } else if (cmp == .equal_equal and zn < 3) {
                    zero_names[zn] = tree.tokenSlice(ct);
                    zn += 1;
                }
                ct += 2;
                continue;
            }
        }

        if (nz > 0) {
            try out.append(gpa, .{
                .names = nonzero_names,
                .n = nz,
                .first = tree.firstToken(ifd.ast.then_expr),
                .last = tree.lastToken(ifd.ast.then_expr),
            });
        }
        if (zn > 0) {
            if (ifd.ast.else_expr.unwrap()) |else_node| {
                try out.append(gpa, .{
                    .names = zero_names,
                    .n = zn,
                    .first = tree.firstToken(else_node),
                    .last = tree.lastToken(else_node),
                });
            }
        }
    }
    return out;
}

/// True when `node` is an array-init literal whose element list (between
/// `{` and `}`) contains only positive integer literals (no zero, no
/// variable references).  Handles all `array_init*` node variants.
fn isAllPositiveLiterals(
    tree: *const Ast,
    ttags: []const std.zig.Token.Tag,
    node: Ast.Node.Index,
) bool {
    const ntag = tree.nodeTag(node);
    switch (ntag) {
        .array_init,
        .array_init_comma,
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        => {},
        else => return false,
    }
    // Find the opening `{` in the node's token range.
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    var brace: ?Ast.TokenIndex = null;
    var t = first;
    while (t <= last) : (t += 1) {
        if (ttags[t] == .l_brace) { brace = t; break; }
    }
    const open = brace orelse return false;
    // Scan element tokens between `{` and `}`.
    var has_elem = false;
    t = open + 1;
    while (t < last) : (t += 1) {
        switch (ttags[t]) {
            .number_literal => {
                const val = std.fmt.parseUnsigned(u64, tree.tokenSlice(t), 0) catch return false;
                if (val == 0) return false;
                has_elem = true;
            },
            .comma, .r_brace => {},
            else => return false, // identifier, operator, etc. → not a pure literal
        }
    }
    return has_elem;
}

/// True when the subscript `[` at `t` is inside a guarded if-body AND
/// one of `check_names` matches a guard identifier from that range.
fn isInGuardedRange(
    ranges: []const GuardedRange,
    t: Ast.TokenIndex,
    check_names: []const []const u8,
) bool {
    for (ranges) |r| {
        if (t < r.first or t > r.last) continue;
        for (check_names) |cn| {
            for (r.names[0..r.n]) |gn| {
                if (std.mem.eql(u8, cn, gn)) return true;
            }
        }
    }
    return false;
}

/// Returns true when `assert(...)` within 30 tokens before `[` contains
/// `GUARD_IDENT (> | !=) 0` anywhere inside the call — including compound
/// conditions like `assert(a > 0 and b.len > 0)` and OR-short-circuit forms
/// like `assert(x == 0 or arr[x - 1] < limit)`.
///
/// Scans up to 24 tokens inside the `assert(` for any simple or dotted
/// zero-guard pattern, stopping at the first `r_paren` at depth 0.
fn hasAssertGuard(
    tags: []const std.zig.Token.Tag,
    tree: *const Ast,
    t: Ast.TokenIndex,
    guard_names: []const []const u8,
) bool {
    if (t < 6) return false;
    const window: u32 = 50;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(k), "assert")) continue;
        if (k + 1 >= t or tags[k + 1] != .l_paren) continue;

        // Scan inside assert( ... ) for any IDENT (> | !=) 0 pattern.
        // Stop at the first unbalanced `)` or after 24 tokens.
        var depth: u32 = 1;
        var ct = k + 2;
        while (ct < t and ct < k + 26) : (ct += 1) {
            if (tags[ct] == .l_paren) { depth += 1; continue; }
            if (tags[ct] == .r_paren) {
                if (depth == 0) break;
                depth -= 1;
                if (depth == 0) break;
                continue;
            }
            if (tags[ct] != .identifier) continue;

            // Dotted: OUTER . INNER (> | !=) 0
            if (ct + 4 < t and
                tags[ct + 1] == .period and
                tags[ct + 2] == .identifier and
                (tags[ct + 3] == .angle_bracket_right or tags[ct + 3] == .bang_equal) and
                tags[ct + 4] == .number_literal and
                std.mem.eql(u8, tree.tokenSlice(ct + 4), "0"))
            {
                const outer_id = tree.tokenSlice(ct);
                const inner_id = tree.tokenSlice(ct + 2);
                for (guard_names) |gn| {
                    if (std.mem.eql(u8, outer_id, gn) or std.mem.eql(u8, inner_id, gn)) return true;
                }
            }

            // Simple: IDENT (> | !=) 0
            if (ct + 2 < t and
                (tags[ct + 1] == .angle_bracket_right or tags[ct + 1] == .bang_equal) and
                tags[ct + 2] == .number_literal and
                std.mem.eql(u8, tree.tokenSlice(ct + 2), "0"))
            {
                const guard_id = tree.tokenSlice(ct);
                for (guard_names) |gn| {
                    if (std.mem.eql(u8, guard_id, gn)) return true;
                }
            }

            // OR-short-circuit: `IDENT == 0 keyword_or` — the RHS of the `or`
            // is only evaluated when IDENT != 0, so subscripts in the RHS are safe.
            // Covers `assert(offset == 0 or arr[offset - 1] < key)`.
            if (ct + 3 < t and
                tags[ct + 1] == .equal_equal and
                tags[ct + 2] == .number_literal and
                std.mem.eql(u8, tree.tokenSlice(ct + 2), "0") and
                tags[ct + 3] == .keyword_or)
            {
                const guard_id = tree.tokenSlice(ct);
                for (guard_names) |gn| {
                    if (std.mem.eql(u8, guard_id, gn)) return true;
                }
            }
        }
    }
    return false;
}

/// Returns true when an early-return guard `if (GUARD == 0) return …`
/// precedes the subscript at `t` within 45 tokens.
///
/// The guard ensures execution only reaches `[` when GUARD != 0.
/// Semicolons between the return statement and `[` are allowed.
///
/// Matched patterns:
///   Simple: `if ( GUARD_IDENT == 0 ) keyword_return`  (return within 3 tok of `)`)
///   Dotted: `if ( OUTER . INNER == 0 ) keyword_return`
fn hasEarlyReturnGuard(
    tags: []const std.zig.Token.Tag,
    tree: *const Ast,
    t: Ast.TokenIndex,
    guard_names: []const []const u8,
) bool {
    if (t < 8) return false;
    const window: u32 = 45;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] != .keyword_if) continue;

        // Simple: `if ( GUARD_IDENT == 0 ) keyword_return`
        //   condition closes at k+5; return must appear within 3 tokens of it.
        if (k + 6 < t and
            tags[k + 1] == .l_paren and
            tags[k + 2] == .identifier and
            tags[k + 3] == .equal_equal and
            tags[k + 4] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(k + 4), "0") and
            tags[k + 5] == .r_paren)
        {
            if (hasExitWithin(tags, k + 6, k + 9, t)) {
                const guard_id = tree.tokenSlice(k + 2);
                for (guard_names) |gn| {
                    if (std.mem.eql(u8, guard_id, gn)) return true;
                }
            }
        }

        // Dotted: `if ( OUTER . INNER == 0 ) keyword_return`
        //   condition closes at k+7; return within 3 tokens.
        if (k + 8 < t and
            tags[k + 1] == .l_paren and
            tags[k + 2] == .identifier and
            tags[k + 3] == .period and
            tags[k + 4] == .identifier and
            tags[k + 5] == .equal_equal and
            tags[k + 6] == .number_literal and
            std.mem.eql(u8, tree.tokenSlice(k + 6), "0") and
            tags[k + 7] == .r_paren)
        {
            if (hasExitWithin(tags, k + 8, k + 11, t)) {
                const outer_id = tree.tokenSlice(k + 2);
                const inner_id = tree.tokenSlice(k + 4);
                for (guard_names) |gn| {
                    if (std.mem.eql(u8, outer_id, gn) or std.mem.eql(u8, inner_id, gn)) return true;
                }
            }
        }
    }
    return false;
}

/// True if `return`, `continue`, or `break` appears in [from, min(to, bound)).
/// All three exit the current execution path, so when any follows `if (x == 0)`,
/// the code after the if is only reached when `x != 0`.
fn hasExitWithin(tags: []const std.zig.Token.Tag, from: Ast.TokenIndex, to: Ast.TokenIndex, bound: Ast.TokenIndex) bool {
    const end = @min(to, bound);
    var i = from;
    while (i < end) : (i += 1) {
        switch (tags[i]) {
            .keyword_return, .keyword_continue, .keyword_break => return true,
            else => {},
        }
    }
    return false;
}

/// True when `IDENT [ 0 ]` appears within 40 tokens before `t` and IDENT
/// matches one of `guard_names`.  Accessing index 0 of a slice/array asserts
/// it is non-empty, so `slice[slice.len - 1]` later in the same expression
/// or statement is safe.
fn hasZeroAccessGuard(
    tags: []const std.zig.Token.Tag,
    tree: *const Ast,
    t: Ast.TokenIndex,
    guard_names: []const []const u8,
) bool {
    if (t < 4) return false;
    const window: u32 = 40;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] != .identifier) continue;
        if (k + 3 >= t) continue;
        if (tags[k + 1] != .l_bracket) continue;
        if (tags[k + 2] != .number_literal or !std.mem.eql(u8, tree.tokenSlice(k + 2), "0")) continue;
        if (tags[k + 3] != .r_bracket) continue;
        const id = tree.tokenSlice(k);
        for (guard_names) |gn| {
            if (std.mem.eql(u8, id, gn)) return true;
        }
    }
    return false;
}

/// True when `IDENT += 1` appears within 35 tokens before `t`.  After
/// `x += 1`, x ≥ 1, so `arr[x - 1]` is in bounds.
fn hasIncrementGuard(
    tags: []const std.zig.Token.Tag,
    tree: *const Ast,
    t: Ast.TokenIndex,
    guard_names: []const []const u8,
) bool {
    if (t < 3) return false;
    const window: u32 = 35;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] != .identifier) continue;
        if (k + 2 >= t) continue;
        if (tags[k + 1] != .plus_equal) continue;
        if (tags[k + 2] != .number_literal or !std.mem.eql(u8, tree.tokenSlice(k + 2), "1")) continue;
        const id = tree.tokenSlice(k);
        for (guard_names) |gn| {
            if (std.mem.eql(u8, id, gn)) return true;
        }
    }
    return false;
}

/// True when `IDENT ... = 1` (initialized to 1) appears within 50 tokens
/// before `t`.  Looks forward up to 5 tokens from the identifier for `= 1`,
/// skipping an optional `: Type` annotation.  `var x: T = 1` means x starts
/// at 1, making `arr[x - 1]` safe on its first use.
fn hasInitToOneGuard(
    tags: []const std.zig.Token.Tag,
    tree: *const Ast,
    t: Ast.TokenIndex,
    guard_names: []const []const u8,
) bool {
    if (t < 5) return false;
    const window: u32 = 50;
    const start: Ast.TokenIndex = if (t >= window) t - window else 0;
    var k: Ast.TokenIndex = t;
    while (k > start) {
        k -= 1;
        if (tags[k] != .identifier) continue;
        const id = tree.tokenSlice(k);
        var matched = false;
        for (guard_names) |gn| {
            if (std.mem.eql(u8, id, gn)) { matched = true; break; }
        }
        if (!matched) continue;
        // Scan forward up to 5 tokens for `equal number_literal("1")`.
        var j = k + 1;
        while (j < t and j <= k + 5) : (j += 1) {
            if (tags[j] == .equal) {
                if (j + 1 < t and
                    tags[j + 1] == .number_literal and
                    std.mem.eql(u8, tree.tokenSlice(j + 1), "1"))
                    return true;
                break;
            }
        }
    }
    return false;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    lb_tok: Ast.TokenIndex,
    idx_name: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`[{s} - 1]` — if `{s}` is `usize` (or any unsigned type) and equals `0`, the subtraction wraps to `maxInt(usize)`, producing an OOB panic (Debug/Safe) or silent arbitrary-memory read (ReleaseFast); add a `{s} > 0` (or `{s} != 0`) guard before this expression",
        .{ idx_name, idx_name, idx_name, idx_name },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, lb_tok),
        .end = Pos.fromTokenEnd(tree, lb_tok + 4),
        .message = msg,
    });
}

fn reportC(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    lb_tok: Ast.TokenIndex,
    recv: []const u8,
    field: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`[{s}.{s}.len - 1]` — if `{s}.{s}.len` is `0`, the subtraction wraps to `maxInt(usize)`, producing an OOB panic (Debug/Safe) or silent arbitrary-memory read (ReleaseFast); add a `{s}.{s}.len > 0` guard before this expression",
        .{ recv, field, recv, field, recv, field },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, lb_tok),
        .end = Pos.fromTokenEnd(tree, lb_tok + 8),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: basic fires" {
    try testing.expectFires(check, R,
        \\fn prev(items: []const u8, idx: usize) u8 {
        \\    return items[idx - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: field minus one fires" {
    try testing.expectFires(check, R,
        \\const Self = struct { current: usize, items: []const u8 };
        \\fn prev(self: Self) u8 {
        \\    return self.items[self.current - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: idx - 2 does not fire" {
    try testing.expectNoFire(check,
        \\fn f(items: []const u8, idx: usize) u8 {
        \\    return items[idx - 2];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: idx + 1 does not fire" {
    try testing.expectNoFire(check,
        \\fn f(items: []const u8, idx: usize) u8 {
        \\    return items[idx + 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: plain index does not fire" {
    try testing.expectNoFire(check,
        \\fn f(items: []const u8, idx: usize) u8 {
        \\    return items[idx];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: recv.field.len - 1 fires (Form C)" {
    try testing.expectFires(check, R,
        \\const Self = struct { args: []const u8 };
        \\fn deinit(self: *Self) void {
        \\    _ = self.args[self.args.len - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: recv.field.len - 2 does not fire" {
    try testing.expectNoFire(check,
        \\const Self = struct { args: []const u8 };
        \\fn f(self: *Self) void {
        \\    _ = self.args[self.args.len - 2];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A suppressed by and-guard" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, x: usize) u8 {
        \\    return if (x > 0 and buf[x - 1] == 0) 1 else 0;
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A suppressed by != 0 and-guard" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, x: usize) u8 {
        \\    return if (x != 0 and buf[x - 1] == 0) 1 else 0;
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A fires when guard uses different ident" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, x: usize, y: usize) u8 {
        \\    return if (y > 0 and buf[x - 1] == 0) 1 else 0;
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form B suppressed by and-guard on outer ident" {
    try testing.expectNoFire(check,
        \\fn f(items: []const u8, s: anytype) bool {
        \\    return s.len > 0 and items[s.len - 1] == 0;
        \\}
        \\
    );
}

// ── If-body guard tests ────────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: Form A suppressed by if-body guard (simple)" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, x: usize) void {
        \\    if (x > 0) assert(buf[x - 1] == 0);
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A suppressed by if-body guard (!= 0)" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, x: usize) void {
        \\    if (x != 0) doSomething(buf[x - 1]);
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A fires when guard uses different ident (if-body)" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, x: usize, y: usize) void {
        \\    if (y > 0) _ = buf[x - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A fires when if guard is followed by semicolon" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, x: usize) void {
        \\    if (x > 0) doSomething();
        \\    _ = buf[x - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form A suppressed inside multi-statement block" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, x: usize) void {
        \\    if (x > 0) {
        \\        doSomething();
        \\        _ = buf[x - 1];
        \\    }
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form B suppressed by if-body guard (dotted)" {
    try testing.expectNoFire(check,
        \\fn f(arr: []const u8, s: anytype) void {
        \\    if (s.len > 0) assert(arr[s.len - 1] == 0);
        \\}
        \\
    );
}

// ── Assert guard tests ─────────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: Form A suppressed by assert guard (simple)" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, n: usize) u8 {
        \\    assert(n > 0);
        \\    return buf[n - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form B suppressed by assert guard (dotted)" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, s: anytype) u8 {
        \\    assert(s.len > 0);
        \\    return buf[s.len - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: assert guard with != 0 suppresses" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, n: usize) u8 {
        \\    assert(n != 0);
        \\    return buf[n - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: assert guard on different ident still fires" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, n: usize, m: usize) u8 {
        \\    assert(m > 0);
        \\    return buf[n - 1];
        \\}
        \\
    );
}

// ── Early-return guard tests ───────────────────────────────────────────────

test "index-minus-one-without-zero-guard: Form A suppressed by early-return guard" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, n: usize) !u8 {
        \\    if (n == 0) return error.Empty;
        \\    return buf[n - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: Form B suppressed by early-return guard (dotted)" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, s: anytype) !u8 {
        \\    if (s.len == 0) return error.Empty;
        \\    return buf[s.len - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: early-return guard on different ident still fires" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, n: usize, m: usize) !u8 {
        \\    if (m == 0) return error.Empty;
        \\    return buf[n - 1];
        \\}
        \\
    );
}

// ── Comptime context tests ─────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: comptime assert suppressed" {
    try testing.expectNoFire(check,
        \\fn f(comptime fmt: []const u8) void {
        \\    comptime assert(fmt[fmt.len - 1] == '\n');
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: runtime access still fires" {
    try testing.expectFires(check, R,
        \\fn f(buf: []const u8, n: usize) u8 {
        \\    return buf[n - 1];
        \\}
        \\
    );
}
// ── Else-body guard tests ──────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: else-body guarded by == 0 condition" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, n: usize) u8 {
        \\    return if (n == 0) 0 else buf[n - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: else-block guarded by == 0 condition" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, idx: usize) u8 {
        \\    if (idx == 0) {
        \\        return 0;
        \\    } else {
        \\        return buf[idx - 1];
        \\    }
        \\}
        \\
    );
}

// ── Compound assert guard tests ────────────────────────────────────────────

test "index-minus-one-without-zero-guard: compound assert (and) suppresses" {
    try testing.expectNoFire(check,
        \\fn f(a: []const u8, b: []const u8) u8 {
        \\    assert(a.len > 0 and b.len > 0);
        \\    return b[b.len - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: OR-short-circuit assert suppresses" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, n: usize) bool {
        \\    assert(n == 0 or buf[n - 1] == 0);
        \\    return true;
        \\}
        \\
    );
}

// ── Continue / break guard tests ───────────────────────────────────────────

test "index-minus-one-without-zero-guard: continue guard suppresses" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8) void {
        \\    for (0..buf.len) |i| {
        \\        if (i == 0) continue;
        \\        _ = buf[i - 1];
        \\    }
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: break guard suppresses" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8, i: usize) void {
        \\    if (i == 0) break;
        \\    _ = buf[i - 1];
        \\}
        \\
    );
}

// ── Zero-access guard tests ────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: prior [0] access suppresses" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8) u8 {
        \\    _ = buf[0];
        \\    return buf[buf.len - 1];
        \\}
        \\
    );
}

// ── Increment guard tests ──────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: += 1 before subscript suppresses" {
    try testing.expectNoFire(check,
        \\fn f(arr: []u8, count: *usize) u8 {
        \\    count.* += 1;
        \\    return arr[count.* - 1];
        \\}
        \\
    );
}

// ── Init-to-one guard tests ────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: var x = 1 suppresses" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8) void {
        \\    var count: usize = 1;
        \\    _ = buf[count - 1];
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: loop var starting at 1 suppresses" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8) void {
        \\    var i: usize = 1;
        \\    while (i < buf.len) : (i += 1) {
        \\        _ = buf[i - 1];
        \\    }
        \\}
        \\
    );
}

// ── Constants guard tests ──────────────────────────────────────────────────

test "index-minus-one-without-zero-guard: constants.X - 1 does not fire" {
    try testing.expectNoFire(check,
        \\fn f(levels: anytype) void {
        \\    _ = levels[constants.max_level - 1];
        \\}
        \\
    );
}

// ── For-range (1..N) and literal-array guard tests ────────────────────────

test "index-minus-one-without-zero-guard: for (1..N) capture suppresses" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8) void {
        \\    for (1..buf.len) |i| {
        \\        _ = buf[i - 1];
        \\    }
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: for (2..N) capture suppresses" {
    try testing.expectNoFire(check,
        \\fn f(arr: []const u8) void {
        \\    for (2..arr.len) |i| {
        \\        _ = arr[i - 1];
        \\    }
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: for (0..N) capture still fires" {
    try testing.expectFires(check, R,
        \\fn f(arr: []const u8) void {
        \\    for (0..arr.len) |i| {
        \\        _ = arr[i - 1];
        \\    }
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: inline for over all-positive literals suppresses" {
    try testing.expectNoFire(check,
        \\fn f(blocks: []u8) void {
        \\    inline for ([_]usize{ 7, 6, 5, 4, 3, 2, 1 }) |i| {
        \\        blocks[i] = blocks[i - 1];
        \\    }
        \\}
        \\
    );
}

test "index-minus-one-without-zero-guard: for over array containing 0 still fires" {
    try testing.expectFires(check, R,
        \\fn f(blocks: []u8) void {
        \\    for ([_]usize{ 3, 2, 1, 0 }) |i| {
        \\        blocks[i] = blocks[i - 1];
        \\    }
        \\}
        \\
    );
}
