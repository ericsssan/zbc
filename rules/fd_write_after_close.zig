//! File-descriptor use-after-close detector — `const <X> = try
//! <dir>.<open-method>(...);` binds an OS file handle; `<X>.close();`
//! invalidates it; any subsequent `<X>.<io-method>(...)` /
//! `<X>.<field-access>` reads or writes through a dangling handle.

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
    if (!config_mod.isEnabled(config, .fd_write_after_close)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = lexer.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        try checkBody(gpa, tree, fn_entry.body, problems);
    }
}

const Binding = struct {
    x_name: []const u8,
    name_token: TokenIndex,
    end_token: TokenIndex,
};

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(problem.Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var bindings: std.ArrayListUnmanaged(Binding) = .empty;
    defer bindings.deinit(gpa);

    var walk = scope.BodyWalk.init(tags, first, last);
    while (walk.t + 5 <= last) : (walk.t += 1) {
        if (walk.atNestedFn()) {
            walk.skipNestedFn();
            continue;
        }
        const t = walk.t;
        if (tags[t] != .keyword_const and tags[t] != .keyword_var) continue;
        if (tags[t + 1] != .identifier) continue;

        // Skip optional type annotation.
        var after_name: TokenIndex = t + 2;
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

        var rhs_start: TokenIndex = after_name + 1;
        if (rhs_start <= last and tags[rhs_start] == .keyword_try) rhs_start += 1;
        if (rhs_start + 3 > last) continue;
        if (tags[rhs_start] != .identifier) continue;
        if (tags[rhs_start + 1] != .period) continue;
        if (tags[rhs_start + 2] != .identifier) continue;
        if (tags[rhs_start + 3] != .l_paren) continue;
        if (!isOpenerMethodName(tree.tokenSlice(rhs_start + 2))) continue;

        const sc = lexer.findStmtSemicolon(tags, rhs_start + 4, last) orelse continue;
        try bindings.append(gpa, .{
            .x_name = tree.tokenSlice(t + 1),
            .name_token = t + 1,
            .end_token = sc,
        });
        walk.t = sc;
    }

    for (bindings.items) |b| {
        const close_tok = scope.findReceiverCallSameDepth(tree, b.end_token + 1, last, b.x_name, isCloseMethodName) orelse continue;
        const after_close = lexer.findStmtSemicolon(tree.tokens.items(.tag), close_tok, last) orelse continue;
        const use_tok = scope.findIdentUseInEnclosingScope(tree, after_close + 1, last, b.x_name) orelse continue;
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

fn isCloseMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "close");
}

fn report(
    gpa: std.mem.Allocator,
    problems: *std.ArrayListUnmanaged(problem.Problem),
    tree: *const Ast,
    b: Binding,
    close_tok: TokenIndex,
    use_tok: TokenIndex,
) !void {
    _ = close_tok;
    const msg = try std.fmt.allocPrint(
        gpa,
        "use of `{s}` after `{s}.close()` — the file handle is invalid; subsequent operations through `{s}` read/write through a dangling fd (fd-reuse on POSIX) or a closed handle (Windows)",
        .{ b.x_name, b.x_name, b.x_name },
    );
    errdefer gpa.free(msg);

    const note_label = try std.fmt.allocPrint(gpa, "file handle opened here", .{});
    errdefer gpa.free(note_label);

    var notes = try gpa.alloc(problem.Note, 1);
    errdefer gpa.free(notes);
    notes[0] = .{
        .start = problem.Pos.fromTokenStart(tree, b.name_token),
        .end = problem.Pos.fromTokenEnd(tree, b.name_token),
        .label = note_label,
    };

    try problems.append(gpa, .{
        .rule_id = "fd-write-after-close",
        .severity = .@"error",
        .start = problem.Pos.fromTokenStart(tree, use_tok),
        .end = problem.Pos.fromTokenEnd(tree, use_tok),
        .message = msg,
        .notes = notes,
    });
}

// ── Tests ──────────────────────────────────────────────────

const R = "fd-write-after-close";

test "createFile then close then writeAll fires" {
    try testing.expectFires(check, R,
        \\const std = @import("std");
        \\pub fn buggy(dir: std.fs.Dir) !void {
        \\    const file = try dir.createFile("x", .{});
        \\    file.close();
        \\    try file.writeAll("hi");
        \\}
    );
}

test "defer close doesn't fire" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\pub fn ok(dir: std.fs.Dir) !void {
        \\    const file = try dir.createFile("x", .{});
        \\    defer file.close();
        \\    try file.writeAll("hi");
        \\}
    );
}

test "errdefer close also skipped" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\pub fn ok(dir: std.fs.Dir) !void {
        \\    const file = try dir.createFile("x", .{});
        \\    errdefer file.close();
        \\    try file.writeAll("hi");
        \\    file.close();
        \\}
    );
}

test "close inside catch block (diverges) is skipped" {
    try testing.expectNoFire(check,
        \\const std = @import("std");
        \\pub fn ok(dir: std.fs.Dir) !void {
        \\    const file = try dir.createFile("x", .{});
        \\    file.writeAll("a") catch {
        \\        file.close();
        \\        return;
        \\    };
        \\    try file.writeAll("b");
        \\}
    );
}

test "openFile variant caught" {
    try testing.expectFires(check, R,
        \\const std = @import("std");
        \\pub fn buggy(dir: std.fs.Dir) !void {
        \\    const file = try dir.openFile("x", .{});
        \\    file.close();
        \\    _ = try file.read(undefined);
        \\}
    );
}

test "field access (file.handle) after close fires" {
    try testing.expectFires(check, R,
        \\const std = @import("std");
        \\pub fn buggy(dir: std.fs.Dir) !void {
        \\    const file = try dir.createFile("x", .{});
        \\    file.close();
        \\    const h = file.handle;
        \\    _ = h;
        \\}
    );
}

test "shadowed name in sibling scope doesn't fire" {
    try testing.expectNoFire(check,
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
    );
}
