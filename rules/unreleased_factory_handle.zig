//! GPU/refcounted-factory leak detector — `const <X> = [try]
//! <device>.<create-method>(...);` returns a refcounted handle
//! with initial refcount=1, but the local goes out of scope
//! without `defer <X>.release()` AND the handle isn't transferred
//! out of the fn (no `return <X>;` and no `<self>.<field> = <X>;`).
//!
//! Real-world: hexops/mach commits `ca08255e` and `3d4888f4` —
//! `device.createShaderModule()`, `getQueue()`, etc. each return
//! a fresh ref that the caller must release.  Examples that use
//! the handle transiently (as input to another create call) leak
//! one ref each invocation.
//!
//! Distinct from existing `unreleased-refs-on-error` which catches
//! `manager.reference()` increments on a loop without paired
//! release errdefer — that rule is about the addref side.  This
//! rule is about the INITIAL ref returned by a factory method on
//! the happy path.
//!
//! Detection (purely syntactic, per-fn token walk):
//!   1. Skip comptime type-builder fns.
//!   2. Find `const|var <X> = [try] <recv>.<create>(...);` where
//!      `<create>` is in the GPU-factory allowlist below.
//!   3. Skip if the fn body contains `defer <X>.release()` /
//!      `errdefer <X>.release()` / `defer <X>.deinit()`.
//!   4. Skip if the fn body contains `return <X>;` or
//!      `<self>.<field> = <X>;` (ownership transfer).
//!   5. Skip if `<X>` is passed as an arg to a `set*`/`use*`
//!      method that conventionally takes ownership.
//!   6. Fire on the binding.
//!
//! Create-method allowlist (GPU-flavored):
//!   createShaderModule / createPipelineLayout / createBindGroup
//!   / createBindGroupLayout / createComputePipeline /
//!   createRenderPipeline / createBuffer / createTexture /
//!   createSampler / createCommandEncoder / createComputePassEncoder
//!   / createRenderPassEncoder / createRenderBundleEncoder /
//!   createQuerySet / getQueue / acquireCurrentTexture /
//!   createTextureView.

const std = @import("std");
const Ast = std.zig.Ast;

const problem_mod = @import("../problem.zig");
const config_mod = @import("../config.zig");

const Problem = problem_mod.Problem;
const Pos = problem_mod.Pos;

pub fn check(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    config: *const config_mod.Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    if (!config_mod.isEnabled(config, .unreleased_factory_handle)) return;

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        if (returnsType(tree, node)) continue;
        const body = bodyOf(tree, node) orelse continue;
        try checkBody(gpa, tree, body, problems);
    }
}

const Handle = struct {
    name: []const u8,
    name_token: Ast.TokenIndex,
    method_tok: Ast.TokenIndex,
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

    var handles: std.ArrayListUnmanaged(Handle) = .empty;
    defer handles.deinit(gpa);

    var t: Ast.TokenIndex = first;
    while (t + 5 <= last) : (t += 1) {
        if (tags[t] == .keyword_fn) {
            t = skipNestedFn(tags, t, last);
            continue;
        }
        if (tags[t] != .keyword_const and tags[t] != .keyword_var) continue;
        if (tags[t + 1] != .identifier) continue;
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
        var rhs: Ast.TokenIndex = after_name + 1;
        if (rhs <= last and tags[rhs] == .keyword_try) rhs += 1;
        if (rhs + 3 > last) continue;
        if (tags[rhs] != .identifier) continue;
        if (tags[rhs + 1] != .period) continue;
        if (tags[rhs + 2] != .identifier) continue;
        if (tags[rhs + 3] != .l_paren) continue;
        if (!isFactoryMethodName(tree.tokenSlice(rhs + 2))) continue;
        try handles.append(gpa, .{
            .name = tree.tokenSlice(t + 1),
            .name_token = t + 1,
            .method_tok = rhs + 2,
        });
    }

    for (handles.items) |h| {
        if (handleHasDeferRelease(tree, first, last, h.name)) continue;
        if (handleEscapes(tree, first, last, h.name)) continue;
        try report(gpa, problems, tree, h);
    }
}

fn isFactoryMethodName(name: []const u8) bool {
    // Only `create*` factory methods that reliably return a fresh
    // refcounted handle.  `getQueue` / `acquireCurrentTexture` /
    // similar are deliberately omitted — depending on the
    // implementation they may return a BORROWED pointer to the
    // device's own field rather than a freshly-counted handle,
    // and flagging them produces FPs.
    return std.mem.eql(u8, name, "createShaderModule") or
        std.mem.eql(u8, name, "createPipelineLayout") or
        std.mem.eql(u8, name, "createBindGroup") or
        std.mem.eql(u8, name, "createBindGroupLayout") or
        std.mem.eql(u8, name, "createComputePipeline") or
        std.mem.eql(u8, name, "createRenderPipeline") or
        std.mem.eql(u8, name, "createBuffer") or
        std.mem.eql(u8, name, "createTexture") or
        std.mem.eql(u8, name, "createSampler") or
        std.mem.eql(u8, name, "createCommandEncoder") or
        std.mem.eql(u8, name, "createComputePassEncoder") or
        std.mem.eql(u8, name, "createRenderPassEncoder") or
        std.mem.eql(u8, name, "createRenderBundleEncoder") or
        std.mem.eql(u8, name, "createQuerySet") or
        std.mem.eql(u8, name, "createTextureView");
}

/// True iff `[start, last]` contains `defer <name>.<release-method>()`
/// or `errdefer <name>.<release-method>()`.
fn handleHasDeferRelease(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    name: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 4 <= last) : (t += 1) {
        if (tags[t] != .keyword_defer and tags[t] != .keyword_errdefer) continue;
        var u: Ast.TokenIndex = t + 1;
        // Optional `|err|` capture.
        if (u <= last and tags[u] == .pipe) {
            u += 1;
            while (u <= last and tags[u] != .pipe) : (u += 1) {}
            if (u > last) return false;
            u += 1;
        }
        // Optional `{` (block form).
        if (u <= last and tags[u] == .l_brace) u += 1;
        if (u + 3 > last) continue;
        if (tags[u] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(u), name)) continue;
        if (tags[u + 1] != .period) continue;
        if (tags[u + 2] != .identifier) continue;
        if (tags[u + 3] != .l_paren) continue;
        const m = tree.tokenSlice(u + 2);
        if (isReleaseMethodName(m)) return true;
    }
    return false;
}

fn isReleaseMethodName(name: []const u8) bool {
    return std.mem.eql(u8, name, "release") or
        std.mem.eql(u8, name, "deinit") or
        std.mem.eql(u8, name, "destroy") or
        std.mem.eql(u8, name, "deref") or
        std.mem.eql(u8, name, "unref");
}

/// True iff the handle escapes via:
///   - `return <expr ...name...>` — return statement
///   - `<X> = <expr ...name...>` — assignment RHS (struct-field
///     or `.field = name` in a struct literal)
///   - any place where `<name>` is preceded by `=` (assignment-
///     RHS contexts) — broad enough to catch struct literals,
///     locals, etc.
fn handleEscapes(
    tree: *const Ast,
    start: Ast.TokenIndex,
    last: Ast.TokenIndex,
    name: []const u8,
) bool {
    const tags = tree.tokens.items(.tag);
    var t: Ast.TokenIndex = start;
    while (t + 1 <= last) : (t += 1) {
        if (tags[t] != .identifier) continue;
        if (!std.mem.eql(u8, tree.tokenSlice(t), name)) continue;
        // Skip the binding site itself (`const <name> = ...`).
        if (t >= 1 and (tags[t - 1] == .keyword_const or tags[t - 1] == .keyword_var)) continue;
        if (t >= 2 and tags[t - 2] == .keyword_const and tags[t - 1] != .equal) continue;
        // Preceded by `=` (assignment RHS) → escape.  EXCEPT when
        // the LHS is `_` — that's just an unused-variable silencer,
        // not real transfer.
        if (t >= 1 and tags[t - 1] == .equal) {
            const lhs_is_underscore = t >= 2 and
                tags[t - 2] == .identifier and
                std.mem.eql(u8, tree.tokenSlice(t - 2), "_");
            if (!lhs_is_underscore) return true;
            continue;
        }
        // Preceded by `return` → escape.
        if (t >= 1 and tags[t - 1] == .keyword_return) return true;
        // Preceded by `,` followed by something inside a struct
        // literal or call: `, name,` or `, name)` — count as escape
        // (positional arg / continuation of struct literal).  This
        // is approximate but catches common cases.
        if (t >= 1 and tags[t - 1] == .comma) {
            if (t + 1 <= last and (tags[t + 1] == .comma or tags[t + 1] == .r_paren or tags[t + 1] == .r_brace)) {
                return true;
            }
        }
        // Preceded by `(` and followed by `,` or `)`: positional
        // first arg `foo(name)` or `foo(name, ...)`.
        if (t >= 1 and tags[t - 1] == .l_paren) {
            if (t + 1 <= last and (tags[t + 1] == .comma or tags[t + 1] == .r_paren)) {
                return true;
            }
        }
    }
    return false;
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
    h: Handle,
) !void {
    const method = tree.tokenSlice(h.method_tok);
    const msg = try std.fmt.allocPrint(
        gpa,
        "`{s}` was acquired from `.{s}()` (returns a refcounted handle with initial refcount=1), but no `defer {s}.release()` is registered and the handle isn't returned or stored — one ref leaks every call",
        .{ h.name, method, h.name },
    );
    errdefer gpa.free(msg);

    try problems.append(gpa, .{
        .rule_id = "unreleased-factory-handle",
        .severity = .@"error",
        .start = Pos.fromTokenStart(tree, h.name_token),
        .end = Pos.fromTokenEnd(tree, h.name_token),
        .message = msg,
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

test "unreleased-factory-handle: createPipelineLayout without defer release fires" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const std = @import("std");
        \\const Device = struct {
        \\    pub fn createPipelineLayout(_: *Device, _: anytype) *u8 { return undefined; }
        \\};
        \\pub fn build(device: *Device, desc: anytype) void {
        \\    const layout = device.createPipelineLayout(desc);
        \\    _ = layout;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 1), problems.items.len);
    try std.testing.expectEqualStrings("unreleased-factory-handle", problems.items[0].rule_id);
}

test "unreleased-factory-handle: with defer release doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Layout = struct { pub fn release(_: *Layout) void {} };
        \\const Device = struct {
        \\    pub fn createPipelineLayout(_: *Device, _: anytype) *Layout { return undefined; }
        \\};
        \\pub fn build(device: *Device, desc: anytype) void {
        \\    const layout = device.createPipelineLayout(desc);
        \\    defer layout.release();
        \\    _ = layout;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "unreleased-factory-handle: returned handle doesn't fire (ownership transfer)" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Layout = struct {};
        \\const Device = struct {
        \\    pub fn createPipelineLayout(_: *Device, _: anytype) *Layout { return undefined; }
        \\};
        \\pub fn build(device: *Device, desc: anytype) *Layout {
        \\    const layout = device.createPipelineLayout(desc);
        \\    return layout;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "unreleased-factory-handle: stored in struct field doesn't fire" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Layout = struct {};
        \\const Device = struct {
        \\    pub fn createPipelineLayout(_: *Device, _: anytype) *Layout { return undefined; }
        \\};
        \\const Renderer = struct {
        \\    layout: *Layout,
        \\    pub fn setup(self: *Renderer, device: *Device, desc: anytype) void {
        \\        const layout = device.createPipelineLayout(desc);
        \\        self.layout = layout;
        \\    }
        \\};
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}

test "unreleased-factory-handle: non-factory method (getStatus) skipped" {
    const gpa = std.testing.allocator;
    var problems = try runOn(gpa,
        \\const Device = struct {
        \\    pub fn getStatus(_: *Device) u8 { return 0; }
        \\};
        \\pub fn check(device: *Device) void {
        \\    const status = device.getStatus();
        \\    _ = status;
        \\}
        \\
    );
    defer freeProblems(gpa, &problems);
    try std.testing.expectEqual(@as(usize, 0), problems.items.len);
}
