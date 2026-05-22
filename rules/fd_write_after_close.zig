//! File-descriptor use-after-close detector — `const <X> = try
//! <dir>.<open-method>(...);` binds an OS file handle; `<X>.close();`
//! invalidates it; any subsequent `<X>.<io-method>(...)` /
//! `<X>.<field-access>` reads or writes through a dangling handle.

const std = @import("std");
const Ast = std.zig.Ast;

const sdk = @import("../analysis.zig");
const config_mod = @import("../config.zig");

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(sdk.Problem),
) !void {
    if (!config_mod.isEnabled(config, .fd_write_after_close)) return;

    var proto_buf: [1]Ast.Node.Index = undefined;
    var fns = sdk.iterFnDecls(tree);
    while (fns.next(&proto_buf)) |fn_entry| {
        try checkBody(gpa, tree, fn_entry.body, problems);
    }
}

const Binding = struct {
    x_name: []const u8,
    name_token: sdk.TokenIndex,
    end_token: sdk.TokenIndex,
};

fn checkBody(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    body: Ast.Node.Index,
    problems: *std.ArrayListUnmanaged(sdk.Problem),
) !void {
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(body);
    const last = tree.lastToken(body);

    var bindings: std.ArrayListUnmanaged(Binding) = .empty;
    defer bindings.deinit(gpa);

    var walk = sdk.BodyWalk.init(tags, first, last);
    while (walk.t + 5 <= last) : (walk.t += 1) {
        if (walk.atNestedFn()) {
            walk.skipNestedFn();
            continue;
        }
        const t = walk.t;
        if (tags[t] != .keyword_const and tags[t] != .keyword_var) continue;
        if (tags[t + 1] != .identifier) continue;

        // Skip optional type annotation.
        var after_name: sdk.TokenIndex = t + 2;
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

        var rhs_start: sdk.TokenIndex = after_name + 1;
        if (rhs_start <= last and tags[rhs_start] == .keyword_try) rhs_start += 1;
        if (rhs_start + 3 > last) continue;
        if (tags[rhs_start] != .identifier) continue;
        if (tags[rhs_start + 1] != .period) continue;
        if (tags[rhs_start + 2] != .identifier) continue;
        if (tags[rhs_start + 3] != .l_paren) continue;
        if (!isOpenerMethodName(tree.tokenSlice(rhs_start + 2))) continue;

        const sc = sdk.findStmtSemicolon(tags, rhs_start + 4, last) orelse continue;
        try bindings.append(gpa, .{
            .x_name = tree.tokenSlice(t + 1),
            .name_token = t + 1,
            .end_token = sc,
        });
        walk.t = sc;
    }

    for (bindings.items) |b| {
        const close_tok = sdk.findReceiverCallSameDepth(tree, b.end_token + 1, last, b.x_name, isCloseMethodName) orelse continue;
        const after_close = sdk.findStmtSemicolon(tree.tokens.items(.tag), close_tok, last) orelse continue;
        const use_tok = sdk.findIdentUseInEnclosingScope(tree, after_close + 1, last, b.x_name) orelse continue;
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
    problems: *std.ArrayListUnmanaged(sdk.Problem),
    tree: *const Ast,
    b: Binding,
    close_tok: sdk.TokenIndex,
    use_tok: sdk.TokenIndex,
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

    var notes = try gpa.alloc(sdk.Note, 1);
    errdefer gpa.free(notes);
    notes[0] = .{
        .start = sdk.Pos.fromTokenStart(tree, b.name_token),
        .end = sdk.Pos.fromTokenEnd(tree, b.name_token),
        .label = note_label,
    };

    try problems.append(gpa, .{
        .rule_id = "fd-write-after-close",
        .severity = .@"error",
        .start = sdk.Pos.fromTokenStart(tree, use_tok),
        .end = sdk.Pos.fromTokenEnd(tree, use_tok),
        .message = msg,
        .notes = notes,
    });
}

// ── Tests ──────────────────────────────────────────────────

fn runOn(gpa: std.mem.Allocator, src: []const u8) !std.ArrayListUnmanaged(sdk.Problem) {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    defer tree.deinit(gpa);
    var problems: std.ArrayListUnmanaged(sdk.Problem) = .empty;
    try check(gpa, &tree, &config_mod.Default, &problems);
    return problems;
}

fn freeProblems(gpa: std.mem.Allocator, p: *std.ArrayListUnmanaged(sdk.Problem)) void {
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

test "fd-write-after-close: defer close doesn't fire" {
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

test "fd-write-after-close: field access (file.handle) after close fires" {
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
