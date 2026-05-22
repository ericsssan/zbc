//! Public library API for the zbc escape analyzer.

const std = @import("std");
const Ast = std.zig.Ast;

const cfg_mod = @import("cfg.zig");
const annotations_mod = @import("annotations.zig");
const analyzer_mod = @import("analyzer.zig");
const imports_mod = @import("imports.zig");
const remote_resolver_mod = @import("remote_resolver.zig");
const config_mod = @import("config.zig");
const problem_mod = @import("problem.zig");

const require_borrowed_from = @import("rules/require_borrowed_from.zig");
const aliased_heap_dupe_mod = @import("rules/aliased_heap_dupe.zig");
const clobbered_by_struct_reset_mod = @import("rules/clobbered_by_struct_reset.zig");
const realloc_byte_count_mod = @import("rules/realloc_byte_count.zig");
const asymmetric_field_free_mod = @import("rules/asymmetric_field_free.zig");
const missing_errdefer_between_tries_mod = @import("rules/missing_errdefer_between_tries.zig");
const free_then_try_realloc_mod = @import("rules/free_then_try_realloc.zig");
const destroy_after_deinit_in_loop_mod = @import("rules/destroy_after_deinit_in_loop.zig");
const dead_errdefer_in_result_fn_mod = @import("rules/dead_errdefer_in_result_fn.zig");
const duplicate_errdefer_mod = @import("rules/duplicate_errdefer.zig");
const overwrite_without_deinit_mod = @import("rules/overwrite_without_deinit.zig");
const stack_fallback_escape_mod = @import("rules/stack_fallback_escape.zig");
const unreleased_refs_on_error_mod = @import("rules/unreleased_refs_on_error.zig");
const hashmap_getptr_rehash_mod = @import("rules/hashmap_getptr_rehash.zig");
const arraylist_items_slice_mod = @import("rules/arraylist_items_slice.zig");
const fd_write_after_close_mod = @import("rules/fd_write_after_close.zig");
const slice_of_arena_into_heap_mod = @import("rules/slice_of_arena_into_heap.zig");
const free_without_null_then_check_mod = @import("rules/free_without_null_then_check.zig");
const tagged_union_retag_with_old_payload_read_mod = @import("rules/tagged_union_retag_with_old_payload_read.zig");
const union_deinit_without_inert_reset_mod = @import("rules/union_deinit_without_inert_reset.zig");
const self_undefined_after_destroy_mod = @import("rules/self_undefined_after_destroy.zig");
const missing_errdefer_on_out_param_mod = @import("rules/missing_errdefer_on_out_param.zig");
const reset_skips_pooled_resource_release_mod = @import("rules/reset_skips_pooled_resource_release.zig");
const return_borrowed_payload_mod = @import("rules/return_borrowed_payload.zig");
const unreleased_factory_handle_mod = @import("rules/unreleased_factory_handle.zig");
const memset_undef_after_len_truncation_mod = @import("rules/memset_undef_after_len_truncation.zig");
const publish_then_touch_self_mod = @import("rules/publish_then_touch_self.zig");
const assert_on_untrusted_input_mod = @import("rules/assert_on_untrusted_input.zig");
const missing_deinit_on_composed_owner_mod = @import("rules/missing_deinit_on_composed_owner.zig");
const borrowed_slice_into_out_param_mod = @import("rules/borrowed_slice_into_out_param.zig");
const defer_and_errdefer_free_overlap_mod = @import("rules/defer_and_errdefer_free_overlap.zig");
const sentinel_strip_free_size_mismatch_mod = @import("rules/sentinel_strip_free_size_mismatch.zig");
const move_out_without_restore_mod = @import("rules/move_out_without_restore.zig");
const deinit_order_violates_construction_dep_mod = @import("rules/deinit_order_violates_construction_dep.zig");
const borrowed_slice_into_stack_buffer_returned_mod = @import("rules/borrowed_slice_into_stack_buffer_returned.zig");
const rule_catalog_mod = @import("rule_catalog.zig");

pub const Config = config_mod.Config;
pub const DefaultConfig = config_mod.Default;
pub const Invariant = config_mod.Invariant;
pub const all_invariants = config_mod.all_invariants;
pub const isEnabled = config_mod.isEnabled;
pub const invariantFromName = config_mod.invariantFromName;
pub const Problem = problem_mod.Problem;
pub const Note = problem_mod.Note;
pub const Pos = problem_mod.Pos;
pub const Severity = problem_mod.Severity;
pub const Cache = remote_resolver_mod.Cache;
pub const Rule = rule_catalog_mod.Rule;
pub const rule_catalog = rule_catalog_mod.all;
pub const lookupRule = rule_catalog_mod.lookup;
pub const trace = @import("trace.zig");

pub fn analyzeEscape(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    cache: ?*Cache,
    config: *const Config,
) ![]Problem {
    const src_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        std.Io.Limit.limited(16 * 1024 * 1024),
    );
    defer gpa.free(src_bytes);

    const src = try gpa.allocSentinel(u8, src_bytes.len, 0);
    defer gpa.free(src);
    @memcpy(src[0..src_bytes.len], src_bytes);

    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);

    // Build imap first so the annotation pass (R7) can do cross-file
    // lookups when a remote cache is provided.
    var imap_storage: ?imports_mod.Map = null;
    defer if (imap_storage) |*m| m.deinit(gpa);
    var remote_ctx_storage: ?cfg_mod.RemoteCtx = null;
    var anno_remote: ?annotations_mod.RemoteCtx = null;
    const base_dir = std.fs.path.dirname(path) orelse ".";

    if (cache) |c| {
        imap_storage = try imports_mod.build(gpa, &tree);
        remote_ctx_storage = .{
            .imap = &imap_storage.?,
            .base_dir = base_dir,
            .cache = c,
        };
        anno_remote = .{
            .imap = &imap_storage.?,
            .base_dir = base_dir,
            .cache = c,
        };
    }

    var db = try annotations_mod.buildFull(gpa, &tree, config, anno_remote);
    defer db.deinit(gpa);

    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    errdefer freeProblemsArrayList(gpa, &problems);

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        const remote_ptr: ?*const cfg_mod.RemoteCtx = if (remote_ctx_storage) |*r| r else null;
        var cfg = (try cfg_mod.lowerFunctionFull(
            gpa,
            &tree,
            node,
            &db,
            remote_ptr,
            config,
        )) orelse continue;
        defer cfg.deinit(gpa);
        try analyzer_mod.check(gpa, &cfg, .{ .path = path, .config = config }, &problems);
    }

    // Aliased-heap-dupe (oven-sh/bun#29910) — purely syntactic per-fn check
    // over the parsed tree.  Runs after the per-fn cfg loop so we
    // have a fully-populated Db (flag_owned_fields etc.).
    try aliased_heap_dupe_mod.check(gpa, &tree, &db, config, &problems);

    // Clobbered-by-struct-reset (oven-sh/bun#29854) — purely syntactic
    // per-fn check.  `<obj>.<X> = …;` followed by `<obj>.* = T{…}`
    // that omits `.<X>` silently drops the prior write.
    try clobbered_by_struct_reset_mod.check(gpa, &tree, &db, config, &problems);

    // Realloc-byte-count (oven-sh/bun#29452) — `<x>.realloc(slice, n *
    // @sizeOf(T))` over-allocates by `@sizeOf(T)×`.  Whole-file
    // token scan, no Db dependency.
    try realloc_byte_count_mod.check(gpa, &tree, config, &problems);

    // Asymmetric-field-free (oven-sh/bun#29853) — destructor handles some
    // same-typed sibling fields but omits others.
    try asymmetric_field_free_mod.check(gpa, &tree, &db, config, &problems);

    // Missing-errdefer-between-tries (oven-sh/bun#30169) — `const X =
    // try Type.method(…);` then a later `try` with no errdefer for
    // X registered between.
    try missing_errdefer_between_tries_mod.check(gpa, &tree, &db, config, &problems);

    // Free-then-try-realloc (oven-sh/bun#29968) — `<x>.free(X); X = try
    // alloc(…);` leaves X dangling on alloc failure.  Whole-file
    // token scan.
    try free_then_try_realloc_mod.check(gpa, &tree, config, &problems);

    // Destroy-after-deinit-in-loop (oven-sh/bun#29879) — destructor loops
    // `<h>.deinit();` over pointer-list items without per-item
    // `destroy`.  Whole-file token scan, destructor-fns only.
    try destroy_after_deinit_in_loop_mod.check(gpa, &tree, config, &problems);

    // Dead-errdefer-in-result-fn (oven-sh/bun#27706) — `errdefer` inside a
    // fn returning a parameterized tagged-union (`Result(T)`) is
    // dead because `return .{ .err = e }` doesn't fire errdefers.
    try dead_errdefer_in_result_fn_mod.check(gpa, &tree, config, &problems);

    // Duplicate-errdefer (tigerbeetle/tigerbeetle#2700) — two
    // `errdefer X.deinit();` for the same receiver fire twice on
    // the error path → double-free / assert.
    try duplicate_errdefer_mod.check(gpa, &tree, config, &problems);

    // Overwrite-without-deinit (oven-sh/bun#28633, #29864) —
    // single-field reassignment to a deinit-able field without
    // prior cleanup leaks the old value.
    try overwrite_without_deinit_mod.check(gpa, &tree, &db, config, &problems);

    // Stack-fallback-escape (ghostty-org/ghostty#9885) — value
    // built on `std.heap.stackFallback(N, …).get()` escapes the
    // fn → dangles into caller's stack frame.
    try stack_fallback_escape_mod.check(gpa, &tree, config, &problems);

    // Unreleased-refs-on-error (hexops/mach
    // sysgpu/vulkan.zig:1887) — loop body acquires refcounted refs
    // via `<obj>.<addref>()` and a later `try` runs with no
    // `errdefer <obj>.<release>()` registered.
    try unreleased_refs_on_error_mod.check(gpa, &tree, config, &problems);

    // HashMap getPtr-rehash — `<map>.getPtr(...)` then receiver-
    // matched mutating call (`.put` / `.remove` / `.fetchPut` / …)
    // followed by a use of the borrowed pointer → UAF against
    // table storage.
    try hashmap_getptr_rehash_mod.check(gpa, &tree, config, &problems);

    // ArrayList items-slice — `const X = <list>.items;` then
    // receiver-matched mutating call (`.append` / `.insert` / …)
    // followed by a use of `X` → UAF if the call reallocated.
    try arraylist_items_slice_mod.check(gpa, &tree, config, &problems);

    // FD write-after-close — `const X = try dir.createFile(...);`
    // then `X.close();` then any further use of `X` → operations
    // through a dangling file handle.
    try fd_write_after_close_mod.check(gpa, &tree, config, &problems);

    // Slice-of-arena-into-heap — arena-allocated slice stored
    // into a container with a non-arena allocator → dangles when
    // the local arena's defer-deinit fires at scope exit.
    try slice_of_arena_into_heap_mod.check(gpa, &tree, config, &problems);

    // Free-without-null-then-check — `<alloc>.destroy/free(<r>.<f>)`
    // in a non-destructor fn without `<r>.<f> = null;` reset →
    // slot dangles, later `if (<r>.<f>) |h| use(h);` UAFs.
    try free_without_null_then_check_mod.check(gpa, &tree, config, &problems);

    // Tagged-union retag-with-old-payload-read — `<path> = .{ .NewTag
    // = .{ ... <path>.OldTag... ... } };`.  Reading the old tag's
    // payload while flipping the active tag is undefined on Zig's
    // x86_64 self-hosted backend.
    try tagged_union_retag_with_old_payload_read_mod.check(gpa, &tree, config, &problems);

    // Union deinit-without-inert-reset — switch arm deinit's the
    // payload but doesn't retag the union; in an idempotent
    // reset/clear/end fn the next call fires the same arm and
    // double-frees the already-freed payload.
    try union_deinit_without_inert_reset_mod.check(gpa, &tree, config, &problems);

    // Self-undefined-after-destroy — `<alloc>.destroy(<X>);` then
    // `<X>.* = ...;` or `<X>.<field> = ...;` writes through freed
    // memory (TigerStyle order inverted; canonical order is
    // overwrite-then-free).
    try self_undefined_after_destroy_mod.check(gpa, &tree, config, &problems);

    // Missing-errdefer-on-out-param —
    // `try <out>.<field>.<acquire>(...)` then later `try` with no
    // `errdefer <out>.<field>.deinit(...)` registered — out-param
    // leaks on the later try's error path.
    try missing_errdefer_on_out_param_mod.check(gpa, &tree, config, &problems);

    // Reset-skips-pooled-resource-release — `deinit` releases
    // pool/handle resources but sibling `reset` doesn't.  Callers
    // using `reset` leak the pool slots.
    try reset_skips_pooled_resource_release_mod.check(gpa, &tree, config, &problems);

    // Return-borrowed-payload — `return switch (...) { .Tag =>
    // |v| v, .Other => |v| try alloc.dupe(u8, v) };` — sibling-
    // arm asymmetry; bare-return arm escapes caller's lifetime.
    try return_borrowed_payload_mod.check(gpa, &tree, config, &problems);

    // Unreleased-factory-handle — `const X = device.create*()`
    // without `defer X.release()` and `X` not returned/stored as
    // struct field → refcounted handle leaks.
    try unreleased_factory_handle_mod.check(gpa, &tree, config, &problems);

    // Memset-undef-after-len-truncation — `<X>.<field>.len = N;
    // @memset(<X>.<field>..., undefined);` — memset runs on the
    // already-truncated empty slice, becoming a no-op.
    try memset_undef_after_len_truncation_mod.check(gpa, &tree, config, &problems);

    // Publish-then-touch-self — `queue.push(this);` then `this.field`
    // — consumer thread may have freed `this` before access.
    try publish_then_touch_self_mod.check(gpa, &tree, config, &problems);

    // Assert-on-untrusted-input — `assert(<param>.<field>)` in a
    // parser/decoder fn → crafted input panics the process.
    try assert_on_untrusted_input_mod.check(gpa, &tree, config, &problems);

    // Missing-deinit-on-composed-owner — outer deinit doesn't
    // call `<self>.<field>.deinit()` for a field whose type has
    // a deinit → inner non-memory resources leak.
    try missing_deinit_on_composed_owner_mod.check(gpa, &tree, config, &problems);

    // Borrowed-slice-into-out-param — `defer X.deinit()` +
    // `<out-ptr-param>.* = ...X...` → out-param holds dangling
    // slice once defer fires.
    try borrowed_slice_into_out_param_mod.check(gpa, &tree, config, &problems);

    // Defer-and-errdefer-free-overlap — `defer alloc.free(X);` +
    // `errdefer { ... <lhs> = X; }` + subsequent `try` → on
    // error, errdefer fires (frees NEW, restores OLD into the
    // field), then defer frees OLD → field dangles.
    try defer_and_errdefer_free_overlap_mod.check(gpa, &tree, config, &problems);

    // Sentinel-strip-free-size-mismatch —
    // `alloc.free(X.ptr[0..X.len])` strips sentinel; on `[:0]`
    // slices the allocator's free-size check fails.
    try sentinel_strip_free_size_mismatch_mod.check(gpa, &tree, config, &problems);

    // Move-out-without-restore — `var X = obj.toArrayList()` +
    // fallible op on X without `defer obj.setArrayList(X)` →
    // partial allocation leaks on error.
    try move_out_without_restore_mod.check(gpa, &tree, config, &problems);

    // Deinit-order-violates-construction-dep — `B.deinit()`
    // before `A.deinit()` where `A` was init'd via
    // `.init(&B, ...)` → A's deinit may UAF B.
    try deinit_order_violates_construction_dep_mod.check(gpa, &tree, config, &problems);

    // Borrowed-slice-into-stack-buffer-returned —
    // `<T>.parse(&stack_buf)` result returned → caller holds
    // a struct whose sub-slice fields alias the dead stack buf.
    try borrowed_slice_into_stack_buffer_returned_mod.check(gpa, &tree, config, &problems);

    return problems.toOwnedSlice(gpa);
}

pub fn analyzeHygiene(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) ![]Problem {
    const src_bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        std.Io.Limit.limited(16 * 1024 * 1024),
    );
    defer gpa.free(src_bytes);

    const src = try gpa.allocSentinel(u8, src_bytes.len, 0);
    defer gpa.free(src);
    @memcpy(src[0..src_bytes.len], src_bytes);

    var tree = try Ast.parse(gpa, src, .zig);
    defer tree.deinit(gpa);

    var problems: std.ArrayListUnmanaged(Problem) = .empty;
    errdefer freeProblemsArrayList(gpa, &problems);

    try require_borrowed_from.check(gpa, &tree, .{}, &problems);

    return problems.toOwnedSlice(gpa);
}

pub fn freeProblems(gpa: std.mem.Allocator, slice: []Problem) void {
    for (slice) |*p| p.deinit(gpa);
    gpa.free(slice);
}

fn freeProblemsArrayList(gpa: std.mem.Allocator, list: *std.ArrayListUnmanaged(Problem)) void {
    for (list.items) |*p| p.deinit(gpa);
    list.deinit(gpa);
}

// ── Tests ───────────────────────────────────────────────────────

test "lib API: analyzeEscape end-to-end flags arena escape" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "foo.zig", .data =
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Arena) []const u8 { _ = self; return ""; }
        \\};
        \\pub fn foo() []const u8 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    return arena.text();
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "foo.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file R7 method-style via anytype param + imap scan" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "inner.zig", .data =
        \\const std = @import("std");
        \\pub const Ctx = struct {
        \\    inner: std.heap.ArenaAllocator,
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Ctx) []const u8 { _ = self; return ""; }
        \\};
        \\
    });
    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data =
        \\const inner = @import("inner.zig");
        \\pub const ReExport = inner.Ctx;
        \\// Anytype wrapper — param has no named type to resolve.
        \\// R7 falls back to imap scan; lib's imap contains inner.zig
        \\// which has text() annotated borrowed_from(self).
        \\pub fn anytype_wrap(c: anytype) []const u8 {
        \\    return c.text();
        \\}
        \\
    });
    try tmp.dir.writeFile(tio, .{ .sub_path = "main.zig", .data =
        \\const std = @import("std");
        \\const inner = @import("inner.zig");
        \\const lib = @import("lib.zig");
        \\pub fn caller() []const u8 {
        \\    var local = inner.Ctx{ .inner = std.heap.ArenaAllocator.init(undefined) };
        \\    return lib.anytype_wrap(local);
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "main.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file R7 method-style via AST type-name resolution" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "inner.zig", .data =
        \\const std = @import("std");
        \\pub const Ctx = struct {
        \\    inner: std.heap.ArenaAllocator,
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Ctx) []const u8 { _ = self; return ""; }
        \\};
        \\
    });
    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data =
        \\const inner = @import("inner.zig");
        \\// Method-style delegator across files.  R7 in lib.zig
        \\// resolves `c`'s type to inner.Ctx and finds text() there.
        \\pub fn wrap(c: *const inner.Ctx) []const u8 {
        \\    return c.text();
        \\}
        \\
    });
    try tmp.dir.writeFile(tio, .{ .sub_path = "main.zig", .data =
        \\const std = @import("std");
        \\const lib = @import("lib.zig");
        \\const inner = @import("inner.zig");
        \\pub fn caller() []const u8 {
        \\    var local = inner.Ctx{ .inner = std.heap.ArenaAllocator.init(undefined) };
        \\    return lib.wrap(&local);
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "main.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file R8 inference fires UAF through imported alloc/free wrappers" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "heap_lib.zig", .data =
        \\const std = @import("std");
        \\pub fn xalloc(g: std.mem.Allocator, n: usize) []u8 {
        \\    return g.alloc(u8, n) catch unreachable;
        \\}
        \\pub fn dispose(g: std.mem.Allocator, p: []u8) void {
        \\    g.free(p);
        \\}
        \\
    });
    try tmp.dir.writeFile(tio, .{ .sub_path = "main.zig", .data =
        \\const std = @import("std");
        \\const lib = @import("heap_lib.zig");
        \\pub fn caller(g: std.mem.Allocator) []u8 {
        \\    const buf = lib.xalloc(g, 16);
        \\    lib.dispose(g, buf);
        \\    return buf;
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "main.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "after free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file R10 chain — wrapper fn calls cross-file destroying method" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // lib.zig: T.finalize destroys self.
    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data =
        \\const bun = struct { pub fn destroy(_: anytype) void {} };
        \\pub const T = struct {
        \\    x: u32 = 0,
        \\    pub fn finalize(this: *T) void { bun.destroy(this); }
        \\};
        \\
    });
    // caller.zig:
    //   `destroyT(t)` calls `t.finalize()` — cross-file method call.
    //   R10 should infer @takes(0) on destroyT by resolving
    //   t.finalize → lib.T.finalize (which IS @takes(0)).
    //   Caller `buggy` then sees destroyT(t) as a free and flags
    //   the subsequent use of t.
    try tmp.dir.writeFile(tio, .{ .sub_path = "caller.zig", .data =
        \\const lib = @import("lib.zig");
        \\pub fn destroyT(t: *lib.T) void {
        \\    t.finalize();
        \\}
        \\pub fn buggy(t: *lib.T) void {
        \\    destroyT(t);
        \\    const v = t.x;
        \\    _ = v;
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "caller.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "after free") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file R10 field-chain — wrapper method frees field via cross-file destroy" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // lib.zig: Item.dispose destroys self.
    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data =
        \\const bun = struct { pub fn destroy(_: anytype) void {} };
        \\pub const Item = struct {
        \\    pub fn dispose(this: *Item) void { bun.destroy(this); }
        \\};
        \\
    });
    // caller.zig: Wrapper.cleanup calls this.inner.dispose() — chain
    // resolves to lib.Item.dispose (cross-file), so cleanup should be
    // inferred as ownership_field { param=0, field="inner" }.
    try tmp.dir.writeFile(tio, .{ .sub_path = "caller.zig", .data =
        \\const lib = @import("lib.zig");
        \\pub const Wrapper = struct {
        \\    inner: *lib.Item,
        \\    pub fn cleanup(this: *Wrapper) void {
        \\        this.inner.dispose();
        \\    }
        \\};
        \\pub fn buggy(w: *Wrapper) void {
        \\    w.cleanup();
        \\    const x = w.inner;
        \\    _ = x;
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "caller.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "use of `w.inner`") != null) found = true;
    }
    try std.testing.expect(found);
}

test "lib API: cross-file type-aware lookup disambiguates method overloads" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // lib.zig defines two types with same-named `finalize` method.
    // Only HTMLRewriter.finalize destroys self.
    try tmp.dir.writeFile(tio, .{ .sub_path = "lib.zig", .data =
        \\const bun = struct { pub fn destroy(_: anytype) void {} };
        \\pub const HTMLRewriter = struct {
        \\    pub fn finalize(this: *HTMLRewriter) void { bun.destroy(this); }
        \\};
        \\pub const HTMLRewriterLoader = struct {
        \\    finalized: bool = false,
        \\    pub fn finalize(this: *HTMLRewriterLoader) void { this.finalized = true; }
        \\};
        \\
    });
    // caller.zig uses both — only `r.finalize()` is a real UAF;
    // `l.finalize()` must NOT fire.
    try tmp.dir.writeFile(tio, .{ .sub_path = "caller.zig", .data =
        \\const lib = @import("lib.zig");
        \\pub fn use_rewriter(r: *lib.HTMLRewriter) void {
        \\    r.finalize();
        \\    const x = r;
        \\    _ = x;
        \\}
        \\pub fn use_loader(l: *lib.HTMLRewriterLoader) void {
        \\    l.finalize();
        \\    const x = l;
        \\    _ = x;
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "caller.zig" });
    defer gpa.free(path);

    var cache = Cache.init(gpa, tio);
    defer cache.deinit();

    const problems = try analyzeEscape(gpa, tio, path, &cache, &DefaultConfig);
    defer freeProblems(gpa, problems);

    // Exactly one rewriter UAF site (the `const x = r;` use; the
    // `_ = x;` use is on the alias).  Loader uses must not fire.
    var rewriter_uaf_count: usize = 0;
    var loader_fp_count: usize = 0;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "use of `r`") != null or
            std.mem.indexOf(u8, p.message, "use of `x`") != null)
        {
            rewriter_uaf_count += 1;
        }
        if (std.mem.indexOf(u8, p.message, "use of `l`") != null) loader_fp_count += 1;
    }
    try std.testing.expect(rewriter_uaf_count >= 1);
    try std.testing.expectEqual(@as(usize, 0), loader_fp_count);
}

test "lib API: analyzeEscape with null cache still works on same-file annotations" {
    const gpa = std.testing.allocator;
    const tio = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(tio, .{ .sub_path = "bar.zig", .data =
        \\const std = @import("std");
        \\const Arena = struct {
        \\    /// @returns borrowed_from(self)
        \\    pub fn text(self: *const Arena) []const u8 { _ = self; return ""; }
        \\};
        \\pub fn foo() []const u8 {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    return arena.text();
        \\}
        \\
    });

    const base_dir = try std.fs.path.join(gpa, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer gpa.free(base_dir);
    const path = try std.fs.path.join(gpa, &.{ base_dir, "bar.zig" });
    defer gpa.free(path);

    const problems = try analyzeEscape(gpa, tio, path, null, &DefaultConfig);
    defer freeProblems(gpa, problems);

    var found = false;
    for (problems) |p| {
        if (std.mem.indexOf(u8, p.message, "function-local arena") != null) found = true;
    }
    try std.testing.expect(found);
}

test {
    _ = cfg_mod;
    _ = annotations_mod;
    _ = analyzer_mod;
    _ = imports_mod;
    _ = remote_resolver_mod;
    _ = config_mod;
    _ = problem_mod;
    _ = @import("abstract_state.zig");
    _ = @import("transfer.zig");
    _ = require_borrowed_from;
    _ = rule_catalog_mod;
    // Session rules — each module owns its inline tests.
    _ = aliased_heap_dupe_mod;
    _ = clobbered_by_struct_reset_mod;
    _ = realloc_byte_count_mod;
    _ = asymmetric_field_free_mod;
    _ = missing_errdefer_between_tries_mod;
    _ = free_then_try_realloc_mod;
    _ = destroy_after_deinit_in_loop_mod;
    _ = dead_errdefer_in_result_fn_mod;
    _ = duplicate_errdefer_mod;
    _ = overwrite_without_deinit_mod;
    _ = stack_fallback_escape_mod;
    _ = unreleased_refs_on_error_mod;
    _ = hashmap_getptr_rehash_mod;
    _ = arraylist_items_slice_mod;
    _ = fd_write_after_close_mod;
    _ = slice_of_arena_into_heap_mod;
    _ = free_without_null_then_check_mod;
    _ = tagged_union_retag_with_old_payload_read_mod;
    _ = union_deinit_without_inert_reset_mod;
    _ = self_undefined_after_destroy_mod;
    _ = missing_errdefer_on_out_param_mod;
    _ = reset_skips_pooled_resource_release_mod;
    _ = return_borrowed_payload_mod;
    _ = unreleased_factory_handle_mod;
    _ = memset_undef_after_len_truncation_mod;
    _ = publish_then_touch_self_mod;
    _ = assert_on_untrusted_input_mod;
    _ = missing_deinit_on_composed_owner_mod;
    _ = borrowed_slice_into_out_param_mod;
    _ = defer_and_errdefer_free_overlap_mod;
    _ = sentinel_strip_free_size_mismatch_mod;
    _ = move_out_without_restore_mod;
    _ = deinit_order_violates_construction_dep_mod;
    _ = borrowed_slice_into_stack_buffer_returned_mod;
    _ = @import("lexer.zig");
    _ = @import("scope.zig");
    _ = @import("receiver.zig");
    _ = @import("testing.zig");
    _ = @import("model.zig");
    _ = @import("trace.zig");
    _ = @import("local.zig");
    std.testing.refAllDecls(@This());
}
