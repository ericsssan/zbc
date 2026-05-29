//! Detects slicing from a non-zero constant offset into a slice/array whose
//! length is not checked before the slice expression:
//!
//!   const tail = line[6..];   // BUG: crashes / OOB if line.len < 6
//!
//! In Zig, `buf[N..]` where `buf.len < N` is a safety-checked out-of-bounds
//! error (trapping in Debug/ReleaseSafe, undefined behaviour in ReleaseFast).
//! When `buf` comes from user or network input the length is unconstrained.
//!
//! Fix: check `buf.len` before slicing:
//!   if (buf.len < 6) return error.TruncatedInput;
//!   const tail = buf[6..];
//!
//! Real-world shape: oven-sh/bun#31227 (patch/lib.rs Zig-mirror pattern —
//! `line[b"--- a/".len()..] ` panics on a truncated `--- a/` header line),
//! oven-sh/bun#31264 (eql_case_insensitive_ascii OOB when input shorter than
//! the keyword literal).
//!
//! Detection (Tier 1, per-fn body token walk):
//!   1. Scan for `identifier l_bracket number_literal(N) ellipsis2 r_bracket`
//!      where N > 0 (i.e., `buf[N..]`).
//!   2. The number_literal must represent a value > 0 (skip `buf[0..]`).
//!   3. Suppression: if `identifier(buf) period identifier(len)` appears
//!      anywhere in the fn body before the slice token, the programmer is
//!      already consulting `.len` on that buffer — do not fire.
//!   4. Suppression: if the preceding token before `identifier(buf)` is
//!      `period` (chain: `self.buf[N..]`) — the receiver has more context;
//!      skip to reduce noise on deeply-chained field accesses.
//!   5. Suppression: self-advance / consume idiom `buf = buf[N..]` (the slice
//!      is a reassignment of the buffer to a sub-slice of itself). This is the
//!      iterate/consume shape — guarded in practice by a `buf[0]` access, a
//!      loop length guard, or a `startsWith` check — and is categorically
//!      distinct from the "parse a fixed prefix from input" bug this rule
//!      targets (`const tail = line[6..]`). Suppressing it preserves recall on
//!      the real bug shape while removing the dominant FP class.
//!   6. Suppression: a `buf[0]` index access before the slice proves
//!      `buf.len >= 1`, the precondition for `buf[1..]`.  Applied only when
//!      the offset is exactly 1 — a `[0]` access does not prove `len >= N`
//!      for N > 1.
//!   7. Suppression: a `startsWith*(…, buf, "literal")` guard before the slice
//!      proves `buf.len >= literal.len`; when that byte length is >= the
//!      offset, `buf[offset..]` is in-bounds.
//!   8. Suppression: `buf` is a local fixed-size array (`var buf: [K]T` or
//!      `var buf = [_]T{…}`).  Array slicing is compile-time bounds checked,
//!      so a `buf[N..]` that compiles is always in-bounds — it can never be the
//!      runtime OOB this rule targets (a `[]T` slice of unconstrained length).
//!   9. Fire at the `l_bracket` token of the unsafe slice.

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
const R = "slice-from-fixed-offset-without-len-check";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .slice_from_fixed_offset_without_len_check)) return;
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

    var t: Ast.TokenIndex = first;
    while (t + 3 <= last) : (t += 1) {
        // Skip nested fn bodies.
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }

        // Pattern: `identifier l_bracket number_literal ellipsis2 r_bracket`
        //   t+0: identifier (the buffer/slice variable)
        //   t+1: l_bracket
        //   t+2: number_literal (the offset N)
        //   t+3: ellipsis2 (..)
        //   t+4: r_bracket  (we check t+4 <= last)
        if (tags[t] != .identifier) continue;
        if (tags[t + 1] != .l_bracket) continue;
        if (tags[t + 2] != .number_literal) continue;
        if (tags[t + 3] != .ellipsis2) continue;
        if (t + 4 > last) continue;
        if (tags[t + 4] != .r_bracket) continue;

        const offset_str = tree.tokenSlice(t + 2);

        // Skip `buf[0..]` — always safe.
        if (std.mem.eql(u8, offset_str, "0")) continue;

        const buf_name = tree.tokenSlice(t);

        // Suppression: skip if the identifier is a chained field access
        // (`self.buf[N..]`). The receiver provides more context and static
        // analysis becomes very imprecise without type info (Tier 4).
        if (t > first and tags[t - 1] == .period) continue;

        // Suppression: self-advance / consume idiom `buf = buf[N..]` — the
        // slice reassigns the buffer to a sub-slice of itself. This is the
        // iterate/consume shape, not the fixed-prefix-parse shape this rule
        // targets. The `(t - 3) != period` guard avoids matching a field
        // assignment whose field happens to share the local's name
        // (`obj.buf = buf[N..]`).
        if (t >= first + 2 and
            tags[t - 1] == .equal and
            tags[t - 2] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t - 2), buf_name) and
            (t < first + 3 or tags[t - 3] != .period))
        {
            continue;
        }

        // Suppression: if `buf_name.len` appears in the fn body BEFORE
        // this slice, the programmer already consults the length.
        if (lenCheckedBefore(tree, tags, first, t, buf_name)) continue;

        // Suppression: a `buf[0]` index access before the slice proves
        // `buf.len >= 1` on that path — exactly the precondition for the
        // offset-1 slice `buf[1..]`.  Only valid for offset == 1: a `[0]`
        // access does NOT prove `len >= N` for N > 1, so larger offsets still
        // fire.
        if (std.mem.eql(u8, offset_str, "1") and
            indexZeroAccessedBefore(tree, tags, first, t, buf_name)) continue;

        // Suppression: a `startsWith*(…, buf, "literal")` guard before the
        // slice proves `buf.len >= literal.len`.  When the prefix's byte
        // length is >= the slice offset, `buf[offset..]` is safe.
        if (startsWithGuardBefore(tree, tags, first, t, buf_name, offset_str)) continue;

        // Suppression: `buf` is a local fixed-size array (`var buf: [K]T` or
        // `var buf = [_]T{…}`).  A fixed-array slice is compile-time bounds
        // checked — if `buf[N..]` compiles then N <= K — so it can never be the
        // runtime out-of-bounds this rule targets (which is a `[]T` slice whose
        // length is unconstrained).  (Tier 3: local declaration tracking.)
        if (isLocalFixedArray(tree, tags, first, t, buf_name)) continue;

        // Fire at the l_bracket of the unsafe slice.
        try report(gpa, problems, tree, t + 1, buf_name, offset_str);
    }
}

/// Returns true iff `identifier(name) period identifier(len)` appears
/// in the range `[start, end)` — i.e. `name.len` is accessed before the slice.
fn lenCheckedBefore(
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    name: []const u8,
) bool {
    if (start >= end) return false;
    var t: Ast.TokenIndex = start;
    // end is exclusive: we scan [start, end-1].
    while (t + 2 < end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), name)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), "len")) continue;
        return true;
    }
    return false;
}

/// Returns true iff `identifier(name) l_bracket number_literal("0") r_bracket`
/// — i.e. the index access `name[0]` (NOT the slice `name[0..]`) — appears in
/// the range `[start, end)`.  Such an access proves `name.len >= 1` on that
/// path, which is the safety precondition for the offset-1 slice `name[1..]`.
fn indexZeroAccessedBefore(
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    name: []const u8,
) bool {
    if (start >= end) return false;
    var t: Ast.TokenIndex = start;
    while (t + 3 < end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), name)) continue;
        if (tags[t + 1] != .l_bracket) continue;
        if (tags[t + 2] != .number_literal) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t + 2), "0")) continue;
        // `name[0]` ends in `r_bracket`; `name[0..]` ends in `ellipsis2` and
        // must NOT match (it is not a proof that len >= 1).
        if (tags[t + 3] != .r_bracket) continue;
        return true;
    }
    return false;
}

/// Returns true iff a `startsWith*(…, name, "literal")` call appears in
/// `[start, end)` whose prefix has a byte length >= the slice `offset_str`.
///
/// `mem.startsWith(u8, name, prefix)` (and the `bun.strings.startsWith*`
/// variants) guarantee `name.len >= prefix.len`.  When `prefix.len >= offset`,
/// the slice `name[offset..]` is in-bounds.  The matched argument shape is
/// `IDENT(name) comma string_literal` at the top level of the call's argument
/// list (so the leading `u8,` of `std.mem.startsWith` is transparently
/// skipped, and nested calls are ignored).  A `char_literal` second argument
/// (`startsWithChar(name, c)`) proves `name.len >= 1` and matches offset 1.
///
/// Path-insensitive, like the `.len` and `[0]` heuristics: in practice the
/// guard and the slice sit in the same guarded branch.
fn startsWithGuardBefore(
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    name: []const u8,
    offset_str: []const u8,
) bool {
    if (start >= end) return false;
    const offset = std.fmt.parseInt(usize, offset_str, 0) catch return false;
    var t: Ast.TokenIndex = start;
    while (t + 2 < end) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.startsWith(u8, tree.tokenSlice(t), "startsWith")) continue;
        if (tags[t + 1] != .l_paren) continue;

        // Walk the argument list at paren-depth 1, looking for the buffer
        // argument followed by a prefix literal.
        var depth: u32 = 0;
        var k: Ast.TokenIndex = t + 1;
        while (k < end) : (k += 1) {
            if (tags[k] == .l_paren) {
                depth += 1;
            } else if (tags[k] == .r_paren) {
                depth -= 1;
                if (depth == 0) break;
            } else if (depth == 1 and
                k + 2 < end and
                tags[k] == .identifier and
                std.mem.eql(u8, tree.tokenSlice(k), name) and
                tags[k + 1] == .comma)
            {
                if (tags[k + 2] == .string_literal) {
                    if (stringLiteralMinByteLen(tree.tokenSlice(k + 2)) >= offset) return true;
                } else if (tags[k + 2] == .char_literal and offset == 1) {
                    return true;
                }
            }
        }
    }
    return false;
}

/// Returns true iff `name` is declared in `[start, end)` as a local fixed-size
/// array — i.e. its element count is a compile-time constant.  Two forms:
///
///   Array type:    `(const|var) name : [ NUMBER ] …`     (e.g. `[48]u8`)
///   Array literal: `(const|var) name … = [ (_ | NUMBER) ] …`  (e.g. `[_]u8{…}`)
///
/// Slice types (`: []T`), many-item pointers (`: [*]T`), and sentinel slices
/// (`: [:0]T`) are NOT arrays — they have no `number_literal` immediately after
/// `[`, so they are correctly excluded.  Slicing a fixed-size array is
/// compile-time bounds checked, so any `name[N..]` that compiles has N <= K.
fn isLocalFixedArray(
    tree: *const Ast,
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    end: Ast.TokenIndex,
    name: []const u8,
) bool {
    if (start >= end) return false;
    var k: Ast.TokenIndex = start;
    while (k + 1 < end) : (k += 1) {
        if (tags[k] != .keyword_const and tags[k] != .keyword_var) continue;
        if (tags[k + 1] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(k + 1), name)) continue;

        // Form A — array type annotation: `name : [ NUMBER ]`.
        if (k + 4 < end and
            tags[k + 2] == .colon and
            tags[k + 3] == .l_bracket and
            tags[k + 4] == .number_literal) return true;

        // Form B — array literal initializer: `name (: type)? = [ (_ | NUMBER) ]`.
        // Scan forward to the `=` (stopping at the statement's `;`).
        var j: Ast.TokenIndex = k + 2;
        while (j + 3 < end and tags[j] != .semicolon) : (j += 1) {
            if (tags[j] != .equal) continue;
            if (tags[j + 1] != .l_bracket) break; // initializer is not an array literal
            const inner = tags[j + 2];
            const is_inferred = inner == .identifier and std.mem.eql(u8, tree.tokenSlice(j + 2), "_");
            if ((inner == .number_literal or is_inferred) and tags[j + 3] == .r_bracket) return true;
            break;
        }
    }
    return false;
}

/// Lower bound on the decoded byte length of a Zig string-literal token slice
/// (quotes included).  Each escape sequence counts as >= 1 byte; `\u{…}` may
/// decode to more, so the result is a sound lower bound for a `>= offset` test.
fn stringLiteralMinByteLen(slice: []const u8) usize {
    if (slice.len < 2) return 0;
    const content = slice[1 .. slice.len - 1];
    var i: usize = 0;
    var count: usize = 0;
    while (i < content.len) {
        if (content[i] == '\\') {
            i += 1;
            if (i >= content.len) break;
            switch (content[i]) {
                'x' => i += 3, // \xNN
                'u' => { // \u{...}
                    i += 1;
                    while (i < content.len and content[i] != '}') i += 1;
                    i += 1;
                },
                else => i += 1, // \n \t \\ \" \' \r etc.
            }
            count += 1;
        } else {
            i += 1;
            count += 1;
        }
    }
    return count;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    lb_tok: Ast.TokenIndex,
    buf_name: []const u8,
    offset: []const u8,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}[{s}..]` slices from a fixed offset without a prior `{s}.len >= {s}` check — crashes (Debug/Safe) or UB (ReleaseFast) when the slice is shorter than {s} bytes; add `if ({s}.len < {s}) return error.TruncatedInput;` before this slice",
        .{ buf_name, offset, buf_name, offset, offset, buf_name, offset },
    );
    errdefer gpa.free(msg);
    try problems.append(gpa, .{
        .rule_id = R,
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, lb_tok),
        .end = Pos.fromTokenEnd(tree, lb_tok),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

test "slice-from-fixed-offset-without-len-check: basic pattern fires" {
    try testing.expectFires(check, R,
        \\fn parse(line: []const u8) []const u8 {
        \\    return line[6..];
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: larger offset fires" {
    try testing.expectFires(check, R,
        \\fn parse(header: []const u8) []const u8 {
        \\    return header[10..];
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: zero offset does not fire" {
    try testing.expectNoFire(check,
        \\fn f(buf: []const u8) []const u8 {
        \\    return buf[0..];
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: len check before slice suppresses" {
    try testing.expectNoFire(check,
        \\fn parse(line: []const u8) ![]const u8 {
        \\    if (line.len < 6) return error.TruncatedInput;
        \\    return line[6..];
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: chained field access does not fire" {
    try testing.expectNoFire(check,
        \\const S = struct {
        \\    buf: []const u8,
        \\    pub fn tail(self: S) []const u8 {
        \\        return self.buf[4..];
        \\    }
        \\};
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: len consulted anywhere before suppresses" {
    try testing.expectNoFire(check,
        \\fn f(data: []const u8) []const u8 {
        \\    const n = data.len;
        \\    _ = n;
        \\    return data[4..];
        \\}
        \\
    );
}

// ── Self-advance / consume idiom suppression ────────────────

test "slice-from-fixed-offset-without-len-check: self-advance buf = buf[1..] does not fire" {
    try testing.expectNoFire(check,
        \\fn consume(items: []u32) void {
        \\    var remain = items;
        \\    for (items) |it| {
        \\        remain[0] = it;
        \\        remain = remain[1..];
        \\    }
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: self-advance with larger offset does not fire" {
    try testing.expectNoFire(check,
        \\fn skip(input: []const u8) []const u8 {
        \\    var name = input;
        \\    name = name[4..];
        \\    return name;
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: assignment to a different var still fires" {
    try testing.expectFires(check, R,
        \\fn f(key: []const u8) []const u8 {
        \\    var out = key[1..];
        \\    return out;
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: field assign sharing local name still fires" {
    try testing.expectFires(check, R,
        \\const S = struct { buf: []const u8 };
        \\fn f(s: *S, buf: []const u8) void {
        \\    s.buf = buf[2..];
        \\}
        \\
    );
}

// ── buf[0]-access implicit non-empty guarantee (offset 1 only) ──

test "slice-from-fixed-offset-without-len-check: buf[0] access before offset-1 slice suppresses" {
    try testing.expectNoFire(check,
        \\fn f(name: []const u8) []const u8 {
        \\    if (name[0] == '@') {
        \\        return name[1..];
        \\    }
        \\    return name;
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: buf[0] access does NOT suppress offset-2 slice" {
    try testing.expectFires(check, R,
        \\fn f(name: []const u8) []const u8 {
        \\    _ = name[0];
        \\    return name[2..];
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: buf[0..] slice does not count as a [0] proof" {
    try testing.expectFires(check, R,
        \\fn f(name: []const u8) []const u8 {
        \\    const head = name[0..];
        \\    _ = head;
        \\    return name[1..];
        \\}
        \\
    );
}

// ── startsWith-guard length guarantee ───────────────────────

test "slice-from-fixed-offset-without-len-check: startsWith(u8, x, \"--\") suppresses x[2..]" {
    try testing.expectNoFire(check,
        \\fn parse(arg: []const u8) []const u8 {
        \\    if (std.mem.startsWith(u8, arg, "--")) return arg[2..];
        \\    return arg;
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: namespaced startsWith with long prefix suppresses x[8..]" {
    try testing.expectNoFire(check,
        \\fn trim(name_ref: []const u8) []const u8 {
        \\    if (bun.strings.startsWithCaseInsensitiveAscii(name_ref, "-webkit-")) {
        \\        return name_ref[8..];
        \\    }
        \\    return name_ref;
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: startsWith prefix shorter than offset still fires" {
    try testing.expectFires(check, R,
        \\fn parse(arg: []const u8) []const u8 {
        \\    if (std.mem.startsWith(u8, arg, "-")) return arg[4..];
        \\    return arg;
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: startsWith on a different buffer still fires" {
    try testing.expectFires(check, R,
        \\fn parse(arg: []const u8, other: []const u8) []const u8 {
        \\    if (std.mem.startsWith(u8, other, "--")) return arg[2..];
        \\    return arg;
        \\}
        \\
    );
}

// ── Local fixed-size array (Tier 3 declaration tracking) ────

test "slice-from-fixed-offset-without-len-check: sized-array local does not fire" {
    try testing.expectNoFire(check,
        \\fn f() void {
        \\    var buf: [48]u8 = undefined;
        \\    const tail = buf[7..];
        \\    _ = tail;
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: inferred-length array literal local does not fire" {
    try testing.expectNoFire(check,
        \\fn f() void {
        \\    var decimal_buf = [_]u8{ '.', 0 };
        \\    const rest = decimal_buf[1..];
        \\    _ = rest;
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: slice-typed local still fires" {
    try testing.expectFires(check, R,
        \\fn f(input: []const u8) void {
        \\    const buf: []const u8 = input;
        \\    const tail = buf[7..];
        \\    _ = tail;
        \\}
        \\
    );
}

test "slice-from-fixed-offset-without-len-check: slice derived from a fixed array still fires" {
    try testing.expectFires(check, R,
        \\fn f() void {
        \\    var arr: [48]u8 = undefined;
        \\    const sub = arr[0..];
        \\    const tail = sub[7..];
        \\    _ = tail;
        \\}
        \\
    );
}
