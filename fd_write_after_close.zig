//! File-descriptor use-after-close detector — `const <X> = try
//! <dir>.<open-method>(...);` binds an OS file handle; `<X>.close();`
//! invalidates it; any subsequent `<X>.<io-method>(...)` /
//! `<X>.<field-access>` reads or writes through a dangling handle.
//!
//! On POSIX the closed fd may be reassigned by the kernel to an
//! unrelated open() before the dangling use — a classic fd-reuse
//! attack vector that lets a stale write land in a completely
//! different file.  On Windows the handle is invalidated and the
//! call fails with INVALID_HANDLE_VALUE, which most code paths don't
//! check.
//!
//! Same family as [[hashmap-getptr-rehash]] and
//! [[arraylist-items-slice]] — borrow-then-invalidate, this time
//! against OS file handles.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Walk the fn body for `const|var <X> = [try] <recv>.<opener>(`
//!      bindings where `<opener>` is in the allowlist below.
//!   3. From the binding's `;`, scan forward for `<X>.close(...)` at
//!      the SAME lexical block depth, skipping nested blocks
//!      (catch/if/loop bodies don't always execute) and `defer` /
//!      `errdefer` statements (deferred — fires at scope exit, after
//!      every other in-scope use).
//!   4. After the close call, scan for the first use of `<X>` in the
//!      binding's enclosing scope and fire on the use site.
//!
//! Opener allowlist (returns an OS file handle):
//!   createFile / createFileZ / openFile / openFileZ /
//!   openDir / openDirZ / open / openZ / openat / openatZ /
//!   accept / socket.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("problem.zig");
const config_mod = @import("config.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .fd_write_after_close)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        if (returnsType(tree, node)) continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, body, problems);
    }
}

const Binding = struct {
    x_name: []const u8,
    name_token: Ast.TokenIndex,
    end_token: Ast.TokenIndex,
};

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var bindings: std.ArrayListUnmanaged(Binding) = .empty;
    defer bindings.deinit(gpa);

    var t: Ast.TokenIndex = first;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_const and tags[t] != .keyword_var) continue;
        if (tags[t + 1] != .identifier) continue;

        // Optional type annotation.
        var after_name: Ast.TokenIndex = t + 2;
        if (after_name <= last and tags[after_name] == .colon) {
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
        if (after_name > last or tags[after_name] != .equal) continue;

        var rhs_start: Ast.TokenIndex = after_name + 1;
        if (rhs_start <= last and tags[rhs_start] == .keyword_try) rhs_start += 1;
        if (rhs_start + 3 > last) continue;
        // Need `<recv> . <opener> (`.
        if (tags[rhs_start] != .identifier) continue;
        if (tags[rhs_start + 1] != .period) continue;
        if (tags[rhs_start + 2] != .identifier) continue;
        if (tags[rhs_start + 3] != .l_paren) continue;
        if (!isOpenerMethodName(tree.tokenSlice(rhs_start + 2))) continue;

        const sc = findStmtSemicolon(tags, rhs_start + 4, last) orelse continue;
        try bindings.append(gpa, .{
            .x_name = tree.tokenSlice(t + 1),
            .name_token = t + 1,
            .end_token = sc,
        });
        t = sc;
    }

    for (bindings.items) |b| {
        // Find `<X>.close(` at the binding's lexical scope.
        const close_tok = findCloseCall(tree, b.end_token + 1, last, b.x_name) orelse continue;
        const after_close = findStmtSemicolon(tags, close_tok, last) orelse continue;
        // After close, any token use of `<X>` in the same scope is
        // the UAF.  (Reassignment is allowed via `var`, but our
        // first-token-match captures the LHS of an assignment as
        // the use — that's a reasonable diagnostic: even reassigning
        // the same name after explicit close is unusual and worth
        // surfacing.)
        const use_tok = findIdentUse(tree, after_close + 1, last, b.x_name) orelse continue;
        try report(gpa, problems, tree, b, close_tok, use_tok);
    }
}

fn isOpenerMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "createFile") or
        std.mem.eql(u8, name, "createFileZ") or
        std.mem.eql(u8, name, "openFile") or
        std.mem.eql(u8, name, "openFileZ") or
        std.mem.eql(u8, name, "openDir") or
        std.mem.eql(u8, name, "openDirZ") or
        std.mem.eql(u8, name, "open") or
        std.mem.eql(u8, name, "openZ") or
        std.mem.eql(u8, name, "openat") or
        std.mem.eql(u8, name, "openatZ") or
        std.mem.eql(u8, name, "accept") or
        std.mem.eql(u8, name, "socket");
}

/// Scan `[start, last]` for the first `<x>.close(` at the binding's
/// lexical scope.  Stops at the enclosing scope's closing `}`; skips
/// nested blocks and defer/errdefer statements.
fn findCloseCall(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    x_name: []const u8,
) ?Ast.TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var t: Ast.TokenIndex = start;
    while (t + 3 <= last) : (t += 1) {
        if (tags[t] == .l_brace) {
            t = matchBrace(tags, t, last) orelse return null;
            continue;
        }
        if (tags[t] == .r_brace) return null;
        if (tags[t] == .keyword_defer or tags[t] == .keyword_errdefer) {
            t = skipDeferStmt(tags, t, last) orelse return null;
            continue;
        }
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), x_name)) continue;
        if (tags[t + 1] != .period) continue;
        if (tags[t + 2] != .identifier) continue;
        if (tags[t + 3] != .l_paren) continue;
        if (std.mem.eql(u8, tree.tokenSlice(t + 2), "close")) return t + 2;
    }
    return null;
}

fn findIdentUse(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    name: []const u8,
) ?Ast.TokenIndex {
    const tags = tree.tokens.items(.tag);
    if (start > last) return null;
    var depth: u32 = 0;
    var t: Ast.TokenIndex = start;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            .l_brace => depth += 1,
            .r_brace => if (depth == 0) return null else {
                depth -= 1;
            },
            .identifier => if (std.mem.eql(u8, tree.tokenSlice(t), name)) return t,
            else => {},
        }
    }
    return null;
}

fn findStmtSemicolon(
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
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

fn matchBrace(
    tags: []const std.zig.Token.Tag,
    lb: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var depth: u32 = 1;
    var t: Ast.TokenIndex = lb + 1;
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

fn skipDeferStmt(
    tags: []const std.zig.Token.Tag,
    kw: Ast.TokenIndex,
    last: Ast.TokenIndex,
) ?Ast.TokenIndex {
    var t: Ast.TokenIndex = kw + 1;
    if (t <= last and tags[t] == .pipe) {
        t += 1;
        while (t <= last and tags[t] != .pipe) : (t += 1) {}
        if (t > last) return null;
        t += 1;
    }
    if (t > last) return null;
    if (tags[t] == .l_brace) return matchBrace(tags, t, last);
    return findStmtSemicolon(tags, t, last);
}

fn skipNestedFn(
    tags: []const std.zig.Token.Tag,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
) Ast.TokenIndex {
    var t: Ast.TokenIndex = start;
    while (t <= last and tags[t] != .l_brace) : (t += 1) {}
    if (t > last) return last;
    return matchBrace(tags, t, last) orelse last;
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

fn bodyOf(tree: *const Ast, node: Ast.Node.Index) ?Ast.Node.Index {
    if (tree.nodeTag(node) != .fn_decl) return null;
    return tree.nodeData(node).node_and_node[1];
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(Problem),
    tree: *const Ast,
    b: Binding,
    close_tok: Ast.TokenIndex,
    use_tok: Ast.TokenIndex,
) !void {
    _ = close_tok;
    const msg = try std.fmt.allocPrint(
        gpa,
        "use of `{s}` after `{s}.close()` — the file handle is invalid; subsequent operations through `{s}` read/write through a dangling fd (fd-reuse on POSIX) or a closed handle (Windows)",
        .{ b.x_name, b.x_name, b.x_name },
    );
    errdefer gpa.free(msg);

    const note_label = try std.fmt.allocPrint(
        gpa,
        "file handle opened here",
        .{},
    );
    errdefer gpa.free(note_label);

    var notes = try gpa.alloc(problem_mod.Note, 1);
    errdefer gpa.free(notes);
    notes[0] = .{
        .start = Pos.fromTokenStart(tree, b.name_token),
        .end = Pos.fromTokenEnd(tree, b.name_token),
        .label = note_label,
    };

    try problems.append(gpa, .{
        .rule_id = "fd-write-after-close",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, use_tok),
        .end = Pos.fromTokenEnd(tree, use_tok),
        .message = msg,
        .notes = notes,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(Problem) {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);
    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    try check(gpa, &tree, &config_mod.Default, &problems);
    return problems;
}

fn freeProblems(gpa: std.mem.Allocator, p: *std.ArrayListUnmanaged(Problem)) void {
    for (p.items) |*x| x.deinit(gpa);
    p.deinit(gpa);
}

test "fd-write-after-close: createFile then close then writeAll fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn buggy(dir: std.fs.Dir) !void {
        \\    const file = try dir.createFile("x", .{});
        \\    file.close();
        \\    try file.writeAll("hi");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("fd-write-after-close", problems.items[0].rule_id);
}

test "fd-write-after-close: defer close (fires at scope exit) doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(dir: std.fs.Dir) !void {
        \\    const file = try dir.createFile("x", .{});
        \\    defer file.close();
        \\    try file.writeAll("hi");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "fd-write-after-close: errdefer close also skipped" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(dir: std.fs.Dir) !void {
        \\    const file = try dir.createFile("x", .{});
        \\    errdefer file.close();
        \\    try file.writeAll("hi");
        \\    file.close();
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "fd-write-after-close: close inside catch block (diverges) is skipped" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(dir: std.fs.Dir) !void {
        \\    const file = try dir.createFile("x", .{});
        \\    file.writeAll("a") catch {
        \\        file.close();
        \\        return;
        \\    };
        \\    try file.writeAll("b");
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "fd-write-after-close: openFile variant caught" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn buggy(dir: std.fs.Dir) !void {
        \\    const file = try dir.openFile("x", .{});
        \\    file.close();
        \\    _ = try file.read(undefined);
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "fd-write-after-close: field access (file.handle) after close also fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn buggy(dir: std.fs.Dir) !void {
        \\    const file = try dir.createFile("x", .{});
        \\    file.close();
        \\    const h = file.handle;
        \\    _ = h;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
}

test "fd-write-after-close: shadowed name in sibling scope doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\pub fn ok(dir: std.fs.Dir, files: []std.fs.File) !void {
        \\    {
        \\        const file = try dir.createFile("x", .{});
        \\        file.close();
        \\    }
        \\    for (files) |file| {
        \\        _ = file;
        \\    }
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
