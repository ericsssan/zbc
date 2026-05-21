//! PR #30169 detector — `const X = try <Type>.<method>(...);`
//! followed by another `try` in the same function body with NO
//! `errdefer X.deinit();` registered between.  If the second try
//! propagates an error, X's allocation leaks.
//!
//! Detection is purely syntactic per-fn token-walk:
//!   1. Find every `const <X> = try <Type>.<method>(...);`
//!      binding where `<Type>` plausibly has a `deinit` method.
//!   2. From each binding, scan forward for the next `try` keyword.
//!   3. If an `errdefer` referencing `X.deinit` appears between
//!      the binding's semicolon and the next try, the binding is
//!      protected.  Otherwise fire at the binding site.

const std = @import("std");
const Ast = std.zig.Ast;

const annotations_mod = @import("annotations.zig");
const problem_mod = @import("problem.zig");
const config_mod = @import("config.zig");

const Db = annotations_mod.Db;
const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    db: *const Db,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .missing_errdefer_between_tries)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        // Skip comptime type-builder fns (`fn T() type { return
        // struct { … }; }`).  Their body contains nested fn_decls;
        // walking it as one would double-count each inner fn's
        // bindings via the outer wrapper.
        if (returnsType(tree, node)) continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, db, body, problems);
    }
}

fn returnsType(tree: *const Ast, fn_decl: Ast.Node.Index) bool {
    var buf: [1]Ast.Node.Index = undefined;
    const fp = fnProto(tree, &buf, fn_decl) orelse return false;
    const rt = fp.ast.return_type.unwrap() orelse return false;
    const first = tree.firstToken(rt);
    const last = tree.lastToken(rt);
    if (first != last) return false;
    return tree.tokens.items(.tag)[first] == .identifier and
        std.mem.eql(u8, tree.tokenSlice(first), "type");
}

fn fnProto(tree: *const Ast, buf: *[1]Ast.Node.Index, node: Ast.Node.Index) ?Ast.full.FnProto {
    return switch (tree.nodeTag(node)) {
        .fn_decl => switch (tree.nodeTag(tree.nodeData(node).node_and_node[0])) {
            .fn_proto => tree.fnProto(tree.nodeData(node).node_and_node[0]),
            .fn_proto_multi => tree.fnProtoMulti(tree.nodeData(node).node_and_node[0]),
            .fn_proto_one => tree.fnProtoOne(buf, tree.nodeData(node).node_and_node[0]),
            .fn_proto_simple => tree.fnProtoSimple(buf, tree.nodeData(node).node_and_node[0]),
            else => null,
        },
        else => null,
    };
}

const Binding = struct {
    x_name: []const u8,
    /// Token of the bound local's identifier — used as the report
    /// anchor.
    name_token: Ast.TokenIndex,
    /// Token of the statement-terminating semicolon — scan for
    /// subsequent `try` / `errdefer` starts from after this.
    end_token: Ast.TokenIndex,
};

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    db: *const Db,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var bindings: std.ArrayListUnmanaged(Binding) = .empty;
    defer bindings.deinit(gpa);

    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        if (tags[t] != .keyword_const) continue;
        if (t + 4 > last) continue;
        if (tags[t + 1] != .identifier) continue;
        // Skip past optional type annotation: `const X: T = …`.
        var after_name: Ast.TokenIndex = t + 2;
        if (tags[after_name] == .colon) {
            // Advance past the type expression up to `=`.
            var d: u32 = 0;
            while (after_name <= last) : (after_name += 1) {
                switch (tags[after_name]) {
                    .l_paren, .l_brace, .l_bracket => d += 1,
                    .r_paren, .r_brace, .r_bracket => if (d > 0) {
                        d -= 1;
                    },
                    .equal => if (d == 0) break,
                    else => {},
                }
            }
        }
        if (after_name > last) continue;
        if (tags[after_name] != .equal) continue;
        if (after_name + 1 > last) continue;
        if (tags[after_name + 1] != .keyword_try) continue;
        // After `try`: expect `<...>.<Type>.<method>(...)` with a
        // method name from the ownership-transfer allowlist.  Walk
        // the identifier-period chain to find the LAST two idents
        // before the `(` — the second-to-last is the type, the
        // last is the method.
        const try_tok = after_name + 1;
        const parsed = parseTypeMethodAfter(tree, try_tok + 1, last) orelse continue;
        if (!isOwnershipTransferMethod(parsed.method)) continue;
        // Type name must start with an uppercase letter — Zig
        // convention for struct/union/enum types.  Lowercase names
        // are local variables (`gpa.dupe(...)`, `allocator.alloc(...)`)
        // where the receiver is an Allocator, not a heap-owning
        // type with a `deinit` method.
        if (parsed.type_name.len == 0 or parsed.type_name[0] < 'A' or parsed.type_name[0] > 'Z') continue;
        if (!typeHasDeinit(db, parsed.type_name)) continue;

        // Find the binding's terminating semicolon at statement depth.
        const sc = findStmtSemicolon(tags, try_tok + 4, last) orelse continue;
        try bindings.append(gpa, .{
            .x_name = tree.tokenSlice(t + 1),
            .name_token = t + 1,
            .end_token = sc,
        });
        t = sc;
    }

    // For each binding, scan forward for the first subsequent `try`
    // at statement level.  If a `defer` or `errdefer` referencing
    // X's cleanup appears between, the binding is protected.
    // `defer` is even stronger than `errdefer` (runs on success AND
    // failure) and is a common idiom for short-lived owned values.
    for (bindings.items) |b| {
        var has_cleanup = false;
        var found_try = false;
        var u: Ast.TokenIndex = b.end_token + 1;
        while (u <= last) : (u += 1) {
            if (tags[u] == .keyword_defer or tags[u] == .keyword_errdefer) {
                if (cleanupReferencesLocal(tree, u, b.x_name, last)) {
                    has_cleanup = true;
                    break;
                }
            }
            if (tags[u] == .keyword_try) {
                found_try = true;
                break;
            }
        }
        if (found_try and !has_cleanup) {
            try report(gpa, problems, tree, b);
        }
    }
}

const ParsedCall = struct {
    type_name: []const u8,
    method: []const u8,
};

/// Walk forward through an `<ident>.<ident>.<ident>(...)` chain
/// starting at `start`.  Return (type_name, method) where method is
/// the LAST identifier before the `(` and type_name is the one
/// immediately preceding it.  Returns null when the chain isn't at
/// least `<Type>.<method>(`.
fn parseTypeMethodAfter(tree: *const Ast, start: Ast.TokenIndex, last: Ast.TokenIndex) ?ParsedCall {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    var prev_ident: ?Ast.TokenIndex = null;
    var last_ident: ?Ast.TokenIndex = null;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .identifier => {
                prev_ident = last_ident;
                last_ident = t;
            },
            .period => {},
            .l_paren => break,
            else => return null,
        }
    }
    const pi = prev_ident orelse return null;
    const li = last_ident orelse return null;
    if (pi == li) return null;
    return .{ .type_name = tree.tokenSlice(pi), .method = tree.tokenSlice(li) };
}

/// Restricted to the canonical "convert a JS value into an owned
/// Zig value" entry point — `<Type>.fromJS`.  This is the strongest
/// ownership-transfer signal in Bun-style codebases (the result is
/// always heap-backed and needs a matching `deinit`), and gating on
/// it keeps the rule's FP rate at zero.  Broader allowlists (`init`,
/// `create`, `parse`, `dupe`) inflated Bun's hit count tenfold with
/// many borderline / hard-to-verify cases — the narrow gate trades
/// recall for precision.
fn isOwnershipTransferMethod(name: []const u8) bool {
    return std.mem.eql(u8, name, "fromJS");
}

/// True iff `Type` has a `deinit` method discoverable in the Db.
/// Conservative: cross-file / unknown types pass through as true
/// so we don't miss real bugs whose types are declared in another
/// file (the canonical PR #30169 case has `PathLike` in a separate
/// module).  Returns false only when the type IS in the local file
/// AND demonstrably has no `deinit`.
fn typeHasDeinit(db: *const Db, type_name: []const u8) bool {
    if (db.hasType(type_name) and db.lookupTyped(type_name, "deinit") == null) {
        return false;
    }
    return true;
}

/// Starting from `start`, walk tokens at statement depth (paren /
/// brace / bracket all zero) until we find the first `;`.  Returns
/// its index, or null if the stmt's terminating semicolon isn't in
/// `[start, last]`.
fn findStmtSemicolon(tags: []const std.zig.Token.Tag, start: Ast.TokenIndex, last: Ast.TokenIndex) ?Ast.TokenIndex {
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

/// True iff the `defer` / `errdefer` at `kw` references some
/// cleanup call on `X` — `X.<deinit/deref/destroy/close/free>(...)`.
/// Accepts the inline form and the block form `{ … X.cleanup() … }`,
/// with optional capture `|err|` for errdefer.
fn cleanupReferencesLocal(tree: *const Ast, kw: Ast.TokenIndex, x_name: []const u8, last: Ast.TokenIndex) bool {
    const tags = tree.tokens.items(.tag);
    if (kw + 1 > last) return false;
    // Inline form: `<kw> X.<method>(`.
    if (tags[kw + 1] == .identifier and
        std.mem.eql(u8, tree.tokenSlice(kw + 1), x_name) and
        kw + 3 <= last and
        tags[kw + 2] == .period and
        tags[kw + 3] == .identifier and
        isCleanupMethodName(tree.tokenSlice(kw + 3)))
    {
        return true;
    }
    // Optional capture (errdefer only): `errdefer |err| { … }`.
    var scan_start: Ast.TokenIndex = kw + 1;
    if (tags[scan_start] == .pipe) {
        scan_start += 1;
        while (scan_start <= last and tags[scan_start] != .pipe) : (scan_start += 1) {}
        if (scan_start > last) return false;
        scan_start += 1;
    }
    if (scan_start > last or tags[scan_start] != .l_brace) return false;
    var depth: u32 = 1;
    var t: Ast.TokenIndex = scan_start + 1;
    while (t <= last and depth > 0) : (t += 1) {
        switch (tags[t]) {
            .l_brace => depth += 1,
            .r_brace => {
                depth -= 1;
                if (depth == 0) break;
            },
            .identifier => {
                if (!std.mem.eql(u8, tree.tokenSlice(t), x_name)) continue;
                if (t + 2 > last) continue;
                if (tags[t + 1] != .period) continue;
                if (tags[t + 2] != .identifier) continue;
                if (isCleanupMethodName(tree.tokenSlice(t + 2))) return true;
            },
            else => {},
        }
    }
    return false;
}

fn isCleanupMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "deref") or
        std.mem.eql(u8, name, "destroy") or
        std.mem.eql(u8, name, "close") or
        std.mem.eql(u8, name, "free") or
        std.mem.eql(u8, name, "release") or
        std.mem.eql(u8, name, "finalize");
}

fn bodyOf(tree: *const Ast, node: Ast.Node.Index) ?Ast.Node.Index {
    if (tree.nodeTag(node) != .fn_decl) return null;
    return tree.nodeData(node).node_and_node[1];
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    b: Binding,
) !void {
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}` is bound via `try …`, but a later `try` in this scope has no `errdefer {s}.deinit();` between them — `{s}` leaks every time the next `try` propagates an error",
        .{ b.x_name, b.x_name, b.x_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "missing-errdefer-between-tries",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, b.name_token),
        .end = Pos.fromTokenEnd(tree, b.name_token),
        .message = msg,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);
    var db = try annotations_mod.buildFull(gpa, &tree, null, null);
    defer db.deinit(gpa);
    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    try check(gpa, &tree, &db, &config_mod.Default, &problems);
    return problems;
}

fn freeProblems(gpa: std.mem.Allocator, p: *std.ArrayListUnmanaged(Problem)) void {
    for (p.items) |*x| x.deinit(gpa);
    p.deinit(gpa);
}

test "missing-errdefer-between-tries: `fromJS` binding without errdefer fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const PathLike = struct {
        \\    pub fn fromJS(_: usize, _: usize) !?PathLike { return null; }
        \\    pub fn deinit(_: *PathLike) void {}
        \\};
        \\pub fn rename(ctx: usize, a: usize, b: usize) !struct { o: PathLike, n: PathLike } {
        \\    const old_path = try PathLike.fromJS(ctx, a) orelse return error.Invalid;
        \\    const new_path = try PathLike.fromJS(ctx, b) orelse return error.Invalid;
        \\    return .{ .o = old_path, .n = new_path };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("missing-errdefer-between-tries", problems.items[0].rule_id);
}

test "missing-errdefer-between-tries: errdefer between tries is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const PathLike = struct {
        \\    pub fn fromJS(_: usize, _: usize) !?PathLike { return null; }
        \\    pub fn deinit(_: *PathLike) void {}
        \\};
        \\pub fn rename(ctx: usize, a: usize, b: usize) !struct { o: PathLike, n: PathLike } {
        \\    var old_path = try PathLike.fromJS(ctx, a) orelse return error.Invalid;
        \\    errdefer old_path.deinit();
        \\    var new_path = try PathLike.fromJS(ctx, b) orelse return error.Invalid;
        \\    errdefer new_path.deinit();
        \\    return .{ .o = old_path, .n = new_path };
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "missing-errdefer-between-tries: `defer X.deref()` is also accepted as protection" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Str = struct {
        \\    pub fn fromJS(_: usize, _: usize) !?Str { return null; }
        \\    pub fn deref(_: *const Str) void {}
        \\    pub fn deinit(_: *Str) void {}
        \\};
        \\pub fn parse(ctx: usize, v: usize) !void {
        \\    const str = try Str.fromJS(ctx, v) orelse return error.Invalid;
        \\    defer str.deref();
        \\    _ = try otherFallible();
        \\}
        \\fn otherFallible() !void {}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "missing-errdefer-between-tries: lowercase receiver (gpa.dupe) doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn foo(a: std.mem.Allocator) !void {
        \\    const buf = try a.dupe(u8, "abc");
        \\    defer a.free(buf);
        \\    _ = try otherFallible();
        \\}
        \\fn otherFallible() !void {}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "missing-errdefer-between-tries: non-`fromJS` method doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const T = struct {
        \\    pub fn create() !T { return .{}; }
        \\    pub fn deinit(_: *T) void {}
        \\};
        \\pub fn foo() !void {
        \\    const x = try T.create();
        \\    _ = x;
        \\    _ = try otherFallible();
        \\}
        \\fn otherFallible() !void {}
        \\
    );
    defer freeProblems(gpa, &problems);
    // Method is `create`, not `fromJS`; narrow gate skips it.
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
