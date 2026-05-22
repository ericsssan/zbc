//! oven-sh/bun#30169 detector — `const X = try <Type>.<method>(...);`
//! followed by another `try` in the same function body with NO
//! `errdefer X.deinit();` registered between.  If the second try
//! propagates an error, X's allocation leaks.
//!
//! Detection (per-fn binding-walk):
//!   1. Find every `const X = try …<Type>.<method>(...)` binding
//!      where `<method>` ∈ {fromJS} (ownership transfer) OR an
//!      fd-opener (createFile/openFile/...).
//!   2. For ownership-transfer methods, require `<Type>` to be
//!      title-cased AND to have a `deinit` (or be unknown — we
//!      pass through cross-file types conservatively).
//!   3. From each binding, scan forward for the next `try`.  If a
//!      `defer`/`errdefer` referencing X appears between, protected.
//!      Otherwise fire.

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("../lexer.zig");
const local = @import("../local.zig");
const annotations_mod = @import("../annotations.zig");
const problem_mod = @import("../problem.zig");
const testing = @import("../testing.zig");
const config_mod = @import("../config.zig");
const file_cache_mod = @import("../file_cache.zig");

const Db = annotations_mod.Db;
const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;
const R = "missing-errdefer-between-tries";

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    db: *const Db,
    cache: *file_cache_mod.FileCache,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .missing_errdefer_between_tries)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = lexer.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        try checkFn(gpa, tree, cache, db, fn_entry.proto, fn_entry.body, problems);
    }
}

const TrackedBinding = struct {
    x_name: []const u8,
    name_token: Ast.TokenIndex,
    /// Token of the binding's terminating semicolon — scans for
    /// subsequent `try` / `errdefer` start from after this.
    end_token: Ast.TokenIndex,
    is_fd_open: bool,
};

fn checkFn(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *file_cache_mod.FileCache,
    db: *const Db,
    proto: Ast.full.FnProto,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);

    // Cheap pre-scan: skip fns with no `try` at all.
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);
    if (!lexer.hasTokenInRange(tags, first, last, .keyword_try)) return;

    const bindings = try cache.localBindings(proto, body);

    var tracked: std.ArrayListUnmanaged(TrackedBinding) = .empty;
    defer tracked.deinit(gpa);

    for (bindings.items) |b| {
        if (!b.is_const) continue;
        if (b.origin == .param) continue;
        // Must be a try-wrapped binding.  Includes captures
        // (`if (try Loader.fromJS(...)) |x|`) AND const bindings
        // (`const X = try ...`).
        if (!b.wasTryWrapped(tags)) continue;

        // Extract the FIRST call's (type, method) — the OLD walker
        // semantics.  Works for any rhs shape including chains and
        // loop-capture scrutinees.
        const parsed = parseTypeMethodAfter(tree, b.rhs_first + 1, b.rhs_last) orelse continue;

        // For chained calls like `std.fs.cwd().createFile(...)`,
        // the FIRST method (cwd) isn't an opener but the OUTER call
        // (createFile) is.  When asCall is available (.try_method_call
        // origins), check the outermost method as a fallback.
        var meth = parsed.method;
        if (!isOwnershipTransferMethod(meth) and !isFileHandleOpenerMethod(meth)) {
            if (b.asCall()) |c| {
                if (c.outermost_method) |outer| {
                    if (isFileHandleOpenerMethod(outer)) meth = outer;
                }
            }
        }

        var is_fd_open = false;
        if (isOwnershipTransferMethod(meth)) {
            if (parsed.type_name.len == 0 or parsed.type_name[0] < 'A' or parsed.type_name[0] > 'Z') continue;
            if (!typeHasDeinit(db, parsed.type_name)) continue;
        } else if (isFileHandleOpenerMethod(meth)) {
            is_fd_open = true;
        } else continue;

        try tracked.append(gpa, .{
            .x_name = b.name,
            .name_token = b.name_token,
            // local.Binding.rhs_last is the token before `;`.
            .end_token = b.rhs_last + 1,
            .is_fd_open = is_fd_open,
        });
    }

    for (tracked.items) |b| {
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

/// Walk forward through an `<ident>(.<ident>)*(...)` chain starting
/// at `start`.  Returns (type_name, method) where `method` is the
/// LAST identifier before the first `(`, and `type_name` is the
/// one immediately before it.  Returns null when the chain isn't
/// at least `<Type>.<method>(`.
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
/// Zig value" entry point — `<Type>.fromJS`.  Bun's strongest
/// ownership-transfer signal; broadening adds many FPs.
fn isOwnershipTransferMethod(name: []const u8) bool {
    return std.mem.eql(u8, name, "fromJS");
}

/// Methods that return an owned OS file/socket handle; cleanup is
/// `.close()` rather than `.deinit()`.
fn isFileHandleOpenerMethod(name: []const u8) bool {
    return std.mem.eql(u8, name, "createFile") or
        std.mem.eql(u8, name, "createFileZ") or
        std.mem.eql(u8, name, "openFile") or
        std.mem.eql(u8, name, "openFileZ") or
        std.mem.eql(u8, name, "openDir") or
        std.mem.eql(u8, name, "openDirZ") or
        std.mem.eql(u8, name, "openat") or
        std.mem.eql(u8, name, "openatZ") or
        std.mem.eql(u8, name, "open") or
        std.mem.eql(u8, name, "socket") or
        std.mem.eql(u8, name, "accept");
}

/// True iff `Type` has a `deinit` method discoverable in the Db.
/// Conservative: cross-file / unknown types pass through (true) so
/// we don't miss real bugs whose types are declared in another
/// file.  Returns false only when the type IS in the local file
/// AND demonstrably has no `deinit`.
fn typeHasDeinit(db: *const Db, type_name: []const u8) bool {
    if (db.hasType(type_name) and db.lookupTyped(type_name, "deinit") == null) {
        return false;
    }
    return true;
}

/// True iff the `defer` / `errdefer` at `kw` mentions `x_name` in
/// its (inline or block) body.  Any mention is treated as cleanup
/// — covers receiver form (`X.cleanup()`) AND arg form
/// (`self.close_socket(X)`, `alloc.free(X)`).
fn cleanupReferencesLocal(tree: *const Ast, kw: Ast.TokenIndex, x_name: []const u8, last: Ast.TokenIndex) bool {
    const tags = tree.tokens.items(.tag);
    if (kw + 1 > last) return false;
    // Inline form: scan until the next `;` at depth 0.
    if (tags[kw + 1] != .l_brace and tags[kw + 1] != .pipe) {
        var paren: u32 = 0;
        var t: Ast.TokenIndex = kw + 1;
        while (t <= last) : (t += 1) {
            switch (tags[t]) {
                .l_paren => paren += 1,
                .r_paren => if (paren > 0) {
                    paren -= 1;
                },
                .semicolon => if (paren == 0) break,
                .identifier => if (std.mem.eql(u8, tree.tokenSlice(t), x_name)) return true,
                else => {},
            }
        }
        return false;
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
            .identifier => if (std.mem.eql(u8, tree.tokenSlice(t), x_name)) return true,
            else => {},
        }
    }
    return false;
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    b: TrackedBinding,
) !void {
    const cleanup = if (b.is_fd_open) "close" else "deinit";
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}` is bound via `try …`, but a later `try` in this scope has no `errdefer {s}.{s}();` between them — `{s}` leaks every time the next `try` propagates an error",
        .{ b.x_name, b.x_name, cleanup, b.x_name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = R,
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
    var cache = file_cache_mod.FileCache.init(gpa, &tree);
    defer cache.deinit();
    try check(gpa, &tree, &db, &cache, &config_mod.Default, &problems);
    return problems;
}

const freeProblems = testing.freeProblems;

test "fromJS binding without errdefer fires" {
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
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings(R, problems.items[0].rule_id);
}

test "errdefer between tries is OK" {
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
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "defer X.deref() is also accepted as protection" {
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
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "lowercase receiver (gpa.dupe) doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn foo(a: std.mem.Allocator) !void {
        \\    const buf = try a.dupe(u8, "abc");
        \\    defer a.free(buf);
        \\    _ = try otherFallible();
        \\}
        \\fn otherFallible() !void {}
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "file-handle open (createFile/openFile) without errdefer fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn writeAof(dir: std.fs.Dir, path: []const u8) !void {
        \\    const file = try dir.createFile(path, .{});
        \\    try file.sync();
        \\    file.close();
        \\}
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings(R, problems.items[0].rule_id);
}

test "file open with errdefer file.close() is OK" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn writeAof(dir: std.fs.Dir, path: []const u8) !void {
        \\    const file = try dir.createFile(path, .{});
        \\    errdefer file.close();
        \\    try file.sync();
        \\}
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "non-fromJS method doesn't fire" {
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
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
