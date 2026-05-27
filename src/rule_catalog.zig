//! Rule catalog AND pattern-rule dispatch registry.
//!
//! Two complementary lists live here so adding a rule is a one-file edit:
//!
//!   - `all` (type `Rule { id, title, body }`) — catalog metadata for
//!     `--list-rules` / `--explain`.  Body comes from `rules/<id>.md`
//!     via `@embedFile`, so the binary is self-contained.
//!   - `escape_detectors` (type `Detector { id, check }`) — runtime
//!     dispatch list for pattern detectors.  Invariants emitted by
//!     the CFG/worklist pipeline are NOT in this list.
//!
//! Adding a pattern rule:
//!   1. Drop `rules/<new-id>.md` into the repo.
//!   2. Create `rules/<new_id>.zig` exporting `pub fn check(...)`.
//!   3. Append a `Rule` entry to `all` and a `Detector` entry to
//!      `escape_detectors` below.
//!   4. Add the invariant to `config.zig` so it can be toggled.

const std = @import("std");

pub const Rule = struct {
    /// Stable kebab-case identifier.  Also the markdown filename
    /// stem and the string emitted in diagnostics' `error[<id>]:`
    /// header.
    id: []const u8,
    /// One-line description.  Shown by `--list-rules`.
    title: []const u8,
    /// Full markdown explainer.  Shown by `--explain <id>`.
    body: []const u8,
};

pub const all = [_]Rule{
    .{
        .id = "heap-use-after-free",
        .title = "reading or returning a heap pointer after free",
        .body = @embedFile("rules/invariants/heap-use-after-free.md"),
    },
    .{
        .id = "heap-double-free",
        .title = "freeing the same heap pointer twice",
        .body = @embedFile("rules/invariants/heap-double-free.md"),
    },
    .{
        .id = "arena-use-after-kill",
        .title = "reading a value borrowed from an arena after the arena's deinit",
        .body = @embedFile("rules/invariants/arena-use-after-kill.md"),
    },
    .{
        .id = "arena-escape",
        .title = "returning a value borrowed from a function-local arena",
        .body = @embedFile("rules/invariants/arena-escape.md"),
    },
    .{
        .id = "stack-escape",
        .title = "returning a pointer to a function-local stack variable",
        .body = @embedFile("rules/invariants/stack-escape.md"),
    },
    .{
        .id = "use-undefined",
        .title = "reading a value that is still `undefined`",
        .body = @embedFile("rules/invariants/use-undefined.md"),
    },
    .{
        .id = "allocator-mismatch",
        .title = "freeing with an allocator different from the one that allocated",
        .body = @embedFile("rules/invariants/allocator-mismatch.md"),
    },
    .{
        .id = "interior-pointer-destroy",
        .title = "calling a destructor on an interior pointer into a container's storage",
        .body = @embedFile("rules/invariants/interior-pointer-destroy.md"),
    },
    .{
        .id = "heap-leak",
        .title = "destructor of a heap-allocated type never frees `self`",
        .body = @embedFile("rules/invariants/heap-leak.md"),
    },
    .{
        .id = "partial-union-write",
        .title = "tagged-union literal with `try`/`catch return` in payload — tag is written before payload",
        .body = @embedFile("rules/invariants/partial-union-write.md"),
    },
    .{
        .id = "aliased-heap-dupe",
        .title = "dupe returns `T` by value with `var dup = this.*;` — heap-owning fields alias the source",
        .body = @embedFile("rules/heap/aliased-heap-dupe.md"),
    },
    .{
        .id = "clobbered-by-struct-reset",
        .title = "`this.<X> = …;` then `this.* = StructLit{…}` without `.<X>` — heap pointer dropped to default",
        .body = @embedFile("rules/cleanup/clobbered-by-struct-reset.md"),
    },
    .{
        .id = "realloc-byte-count",
        .title = "`allocator.realloc(slice, n * @sizeOf(T))` — Zig's realloc takes ELEMENT count, not bytes",
        .body = @embedFile("rules/heap/realloc-byte-count.md"),
    },
    .{
        .id = "asymmetric-field-free",
        .title = "destructor handles some same-typed fields but omits others — the omitted ones leak",
        .body = @embedFile("rules/cleanup/asymmetric-field-free.md"),
    },
    .{
        .id = "missing-errdefer-between-tries",
        .title = "`const X = try Type.method(…);` then another `try` with no `errdefer X.deinit();` — X leaks on the second error",
        .body = @embedFile("rules/errdefer/missing-errdefer-between-tries.md"),
    },
    .{
        .id = "free-then-try-realloc",
        .title = "`free(X); X = try alloc(…);` without clearing X first — X dangles on alloc failure → double-free in `deinit`",
        .body = @embedFile("rules/heap/free-then-try-realloc.md"),
    },
    .{
        .id = "destroy-after-deinit-in-loop",
        .title = "destructor loops `<h>.deinit();` over pointer-list items without `<allocator>.destroy(<h>);` — heap descriptors leak",
        .body = @embedFile("rules/cleanup/destroy-after-deinit-in-loop.md"),
    },
    .{
        .id = "dead-errdefer-in-result-fn",
        .title = "`errdefer` in a fn returning a `Result(T)` tagged union (not `!T`) — never fires, cleanup silently leaks",
        .body = @embedFile("rules/errdefer/dead-errdefer-in-result-fn.md"),
    },
    .{
        .id = "duplicate-errdefer",
        .title = "two `errdefer X.<cleanup>();` for the same receiver — cleanup runs twice on error → double-free / assert",
        .body = @embedFile("rules/errdefer/duplicate-errdefer.md"),
    },
    .{
        .id = "overwrite-without-deinit",
        .title = "`this.field = X;` for a deinit-able field without prior `this.field.deinit();` — old value leaks",
        .body = @embedFile("rules/cleanup/overwrite-without-deinit.md"),
    },
    .{
        .id = "stack-fallback-escape",
        .title = "value built on a `stackFallback(N, …)` allocator escapes the fn — points at caller's stack buffer",
        .body = @embedFile("rules/borrow/stack-fallback-escape.md"),
    },
    .{
        .id = "unreleased-refs-on-error",
        .title = "loop calls `<obj>.<addref>()` then a later `try` runs with no `errdefer` releasing — refs leak on error",
        .body = @embedFile("rules/errdefer/unreleased-refs-on-error.md"),
    },
    .{
        .id = "hashmap-getptr-rehash",
        .title = "use of `<X>` after `<map>.put/remove/...(...)` — the borrow from `<map>.getPtr/getOrPut(...)` was invalidated",
        .body = @embedFile("rules/collection/hashmap-getptr-rehash.md"),
    },
    .{
        .id = "arraylist-items-slice",
        .title = "use of `<X>` after `<list>.append/insert/...(...)` — the slice borrowed via `<list>.items` was invalidated by a realloc",
        .body = @embedFile("rules/collection/arraylist-items-slice.md"),
    },
    .{
        .id = "fd-write-after-close",
        .title = "use of file handle `<X>` after `<X>.close()` — the fd is invalid; reads/writes go through a dangling fd",
        .body = @embedFile("rules/misc/fd-write-after-close.md"),
    },
    .{
        .id = "slice-of-arena-into-heap",
        .title = "arena-allocated slice stored into a non-arena container — dangles when the local arena's deinit fires",
        .body = @embedFile("rules/heap/slice-of-arena-into-heap.md"),
    },
    .{
        .id = "free-without-null-then-check",
        .title = "freed `<recv>.<field>` without reset — slot now dangles; later `if (<recv>.<field>) |h| use(h);` UAFs",
        .body = @embedFile("rules/heap/free-without-null-then-check.md"),
    },
    .{
        .id = "tagged-union-retag-with-old-payload-read",
        .title = "reading `<path>.<OldTag>` while assigning `.{ .<NewTag> = ... }` to `<path>` — x86_64 backend may evaluate read after tag flip",
        .body = @embedFile("rules/misc/tagged-union-retag-with-old-payload-read.md"),
    },
    .{
        .id = "union-deinit-without-inert-reset",
        .title = "switch arm deinit'd payload but didn't retag the union — idempotent reset/clear/end fn will double-free on next call",
        .body = @embedFile("rules/cleanup/union-deinit-without-inert-reset.md"),
    },
    .{
        .id = "self-undefined-after-destroy",
        .title = "`<X>.* = ...` / `<X>.<field> = ...` after `<alloc>.destroy(<X>);` — write hits freed memory (TigerStyle order inverted)",
        .body = @embedFile("rules/borrow/self-undefined-after-destroy.md"),
    },
    .{
        .id = "missing-errdefer-on-out-param",
        .title = "`try <out>.<field>.<acquire>(...)` then later `try` with no `errdefer <out>.<field>.deinit(...)` — out-param leaks on error",
        .body = @embedFile("rules/errdefer/missing-errdefer-on-out-param.md"),
    },
    .{
        .id = "reset-skips-pooled-resource-release",
        .title = "`deinit` releases pool/handle resources but sibling `reset` doesn't — callers using `reset` leak slots",
        .body = @embedFile("rules/cleanup/reset-skips-pooled-resource-release.md"),
    },
    .{
        .id = "return-borrowed-payload",
        .title = "`return switch (...) { .<Tag> => |v| v, ... }` — bare payload return while sibling arm clones; borrowed value escapes caller's lifetime",
        .body = @embedFile("rules/borrow/return-borrowed-payload.md"),
    },
    .{
        .id = "unreleased-factory-handle",
        .title = "`const <X> = device.create*()` without `defer <X>.release()` and `<X>` not returned/stored — refcounted handle leaks",
        .body = @embedFile("rules/cleanup/unreleased-factory-handle.md"),
    },
    .{
        .id = "memset-undef-after-len-truncation",
        .title = "`@memset(<X>.<field>..., undefined)` AFTER `<X>.<field>.len = ...` truncation — memset is a no-op on the now-empty slice",
        .body = @embedFile("rules/collection/memset-undef-after-len-truncation.md"),
    },
    .{
        .id = "publish-then-touch-self",
        .title = "use of `this`/`self` after publishing it to a concurrent queue — consumer thread may have freed it",
        .body = @embedFile("rules/misc/publish-then-touch-self.md"),
    },
    .{
        .id = "assert-on-untrusted-input",
        .title = "`assert(...)` in a parser/decoder against untrusted-input parameter — crafted bytes panic the process",
        .body = @embedFile("rules/misc/assert-on-untrusted-input.md"),
    },
    .{
        .id = "missing-deinit-on-composed-owner",
        .title = "outer `deinit` doesn't call `<self>.<field>.deinit()` for a field whose type has a deinit — inner resources leak",
        .body = @embedFile("rules/cleanup/missing-deinit-on-composed-owner.md"),
    },
    .{
        .id = "owned-field-no-outer-cleanup",
        .title = "outer struct has a value-typed field whose type exposes `deinit`/`close`/etc., but outer has no cleanup method — dropped values silently leak",
        .body = @embedFile("rules/cleanup/owned-field-no-outer-cleanup.md"),
    },
    .{
        .id = "borrowed-slice-into-out-param",
        .title = "write into pointer out-param uses a `defer ... .deinit()`-bound local — out-param dangles after return",
        .body = @embedFile("rules/borrow/borrowed-slice-into-out-param.md"),
    },
    .{
        .id = "defer-and-errdefer-free-overlap",
        .title = "`defer alloc.free(X)` + `errdefer { ...; <lhs> = X; }` — both fire on error, leaving field dangling",
        .body = @embedFile("rules/errdefer/defer-and-errdefer-free-overlap.md"),
    },
    .{
        .id = "sentinel-strip-free-size-mismatch",
        .title = "`alloc.free(X.ptr[0..X.len])` — strips sentinel; allocator's free-size check fails on `[:0]` slices",
        .body = @embedFile("rules/heap/sentinel-strip-free-size-mismatch.md"),
    },
    .{
        .id = "move-out-without-restore",
        .title = "`var X = obj.toArrayList()` + fallible op on X with no `defer obj.setArrayList(X)` — leak on error",
        .body = @embedFile("rules/cleanup/move-out-without-restore.md"),
    },
    .{
        .id = "deinit-order-violates-construction-dep",
        .title = "`B.deinit()` before `A.deinit()` where `A` was init'd via `.init(&B, ...)` — LIFO violation; A's deinit may UAF",
        .body = @embedFile("rules/cleanup/deinit-order-violates-construction-dep.md"),
    },
    .{
        .id = "borrowed-slice-into-stack-buffer-returned",
        .title = "`<T>.parse(&stack_buf)` result returned — sub-slice fields point at the now-dead stack buffer",
        .body = @embedFile("rules/borrow/borrowed-slice-into-stack-buffer-returned.md"),
    },
    .{
        .id = "getorput-unguarded-value-read",
        .title = "use of `<gop>.value_ptr.*` before checking `<gop>.found_existing` — uninitialised read when the key is new",
        .body = @embedFile("rules/invariants/getorput-unguarded-value-read.md"),
    },
    .{
        .id = "hashmap-iter-mutation",
        .title = "mutation of a HashMap while iterating it — iterator cursor is now undefined",
        .body = @embedFile("rules/invariants/hashmap-iter-mutation.md"),
    },
    .{
        .id = "iterator-invalidation-mutation",
        .title = "`for (list.items)` loop body mutates the list — backing buffer may move or reorder under the iterator",
        .body = @embedFile("rules/invariants/iterator-invalidation-mutation.md"),
    },
    .{
        .id = "thread-spawn-local-pointer",
        .title = "`Thread.spawn` receives `&<local>` — thread outlives the spawning frame; pointer dangles",
        .body = @embedFile("rules/invariants/thread-spawn-local-pointer.md"),
    },
    .{
        .id = "self-pointer-in-returned-value",
        .title = "`<local>.<field> = &<local>; return <local>` — self-referential pointer in returned-by-value struct dangles",
        .body = @embedFile("rules/invariants/self-pointer-in-returned-value.md"),
    },
    .{
        .id = "todo-panic-in-production",
        .title = "`@panic(\"TODO …\")` marker left in production code — crashes users when the branch is reached",
        .body = @embedFile("rules/invariants/todo-panic-in-production.md"),
    },
    .{
        .id = "ref-before-ownership-transfer",
        .title = "`<recv>.<addref>()` before `init(<recv>, …)` — caller bumps refcount, callee decrements once, extra ref leaks",
        .body = @embedFile("rules/heap/ref-before-ownership-transfer.md"),
    },
    .{
        .id = "opt-capture-ptr-after-field-clear",
        .title = "pointer derived from `if (<recv>.<field>) |*<cap>|` payload used after `<recv>.<field> = …` — storage invalidated",
        .body = @embedFile("rules/heap/opt-capture-ptr-after-field-clear.md"),
    },
    .{
        .id = "tagged-union-payload-early-exit",
        .title = "`try` inside single-field union literal assignment — tag written before payload; error exit leaves union in inconsistent state",
        .body = @embedFile("rules/misc/tagged-union-payload-early-exit.md"),
    },
    .{
        .id = "union-payload-ptr-after-variant-change",
        .title = "pointer into union payload taken then variant reassigned — payload storage repurposed, pointer becomes dangling",
        .body = @embedFile("rules/misc/union-payload-ptr-after-variant-change.md"),
    },
    .{
        .id = "flag-reset-after-callback",
        .title = "`<recv>.<in_progress> = false` after function call that may re-enter — re-entrant `true` assignment clobbered",
        .body = @embedFile("rules/misc/flag-reset-after-callback.md"),
    },
    .{
        .id = "slice-loop-reentrant-grow",
        .title = "function call inside `for (<recv>.items)` loop may grow the collection — backing buffer reallocated mid-iteration",
        .body = @embedFile("rules/collection/slice-loop-reentrant-grow.md"),
    },
    .{
        .id = "scope-push-pop-imbalance",
        .title = "`pushScope`/`enterScope`/etc. without `defer popScope` — early returns leave scope stack unbalanced",
        .body = @embedFile("rules/misc/scope-push-pop-imbalance.md"),
    },
    .{
        .id = "exit-callback-cross-thread",
        .title = "at-exit callback accesses `self.` fields without `is_main_thread()` guard — races when exit fires from a worker thread",
        .body = @embedFile("rules/misc/exit-callback-cross-thread.md"),
    },
    .{
        .id = "index-type-narrowing-wraparound",
        .title = "`var NAME: iN = …len…` — narrow signed index wraps when collection exceeds type max; loop never executes or runs backward",
        .body = @embedFile("rules/misc/index-type-narrowing-wraparound.md"),
    },
    .{
        .id = "ref-counted-copy-without-dupe",
        .title = "`.field = recv.field` copies refcounted/owned field without `clone()`/`dupeRef()` — both sides decrement on drop → double-free / SIGFPE",
        .body = @embedFile("rules/misc/ref-counted-copy-without-dupe.md"),
    },
    .{
        .id = "arraybuffer-slice-without-pin",
        .title = "raw slice from JSC-managed buffer live across GC-trigger call — backing buffer may be moved or freed",
        .body = @embedFile("rules/collection/arraybuffer-slice-without-pin.md"),
    },
    .{
        .id = "optional-fallback-wrong-side",
        .title = "`recv.remoteField orelse recv.localField` — peer-advertised value falls back to local-config limit; verify `orelse` direction",
        .body = @embedFile("rules/misc/optional-fallback-wrong-side.md"),
    },
    .{
        .id = "escape-skip-without-bounds-recheck",
        .title = "`if (buf[i] == '\\\\') { i += 1; }` followed by unconditional `i += 1` without bounds guard — OOB read when escape char is last byte",
        .body = @embedFile("rules/misc/escape-skip-without-bounds-recheck.md"),
    },
    .{
        .id = "recursive-parse-fn-without-stack-check",
        .title = "recursive parse/skip/visit/scan fn calls itself without `is_safe_to_recurse()` guard — deep input overflows the call stack",
        .body = @embedFile("rules/misc/recursive-parse-fn-without-stack-check.md"),
    },
    .{
        .id = "slice-from-fixed-offset-without-len-check",
        .title = "`buf[N..]` from a non-zero literal offset without a prior `buf.len >= N` check — OOB trap (Debug/Safe) or UB (ReleaseFast)",
        .body = @embedFile("rules/misc/slice-from-fixed-offset-without-len-check.md"),
    },
    .{
        .id = "negate-then-shift-without-minint-check",
        .title = "`-value << N` without `minInt` guard — overflow when value == minInt(T), producing garbage or UB in ReleaseFast",
        .body = @embedFile("rules/misc/negate-then-shift-without-minint-check.md"),
    },
    .{
        .id = "readint-unchecked-position-assignment",
        .title = "`readInt`-deserialized value assigned to position/cursor field without bounds check — OOB when used to slice buffer",
        .body = @embedFile("rules/misc/readint-unchecked-position-assignment.md"),
    },
    .{
        .id = "arraylist-sentinel-write-without-capacity",
        .title = "`list.items[list.items.len] = …` — write past end of ArrayList without `ensureUnusedCapacity`; OOB trap or heap corruption",
        .body = @embedFile("rules/collection/arraylist-sentinel-write-without-capacity.md"),
    },
    .{
        .id = "intfromfloat-without-clamp",
        .title = "`@intFromFloat(x)` without `@min`/`@max`/`clamp` guard — panics on ±Inf, NaN, or out-of-range float (UB in ReleaseFast)",
        .body = @embedFile("rules/misc/intfromfloat-without-clamp.md"),
    },
    .{
        .id = "int-sum-overflow-in-bounds-cmp",
        .title = "`data.len < (a + b)` bounds check — sum computed in narrower type wraps to small value, bypassing the guard",
        .body = @embedFile("rules/misc/int-sum-overflow-in-bounds-cmp.md"),
    },
    .{
        .id = "ptr-slice-without-bounds-check",
        .title = "`.ptr[0..N]` for N∈{2,3,4} bypasses slice length check — OOB read when slice has fewer than N bytes",
        .body = @embedFile("rules/misc/ptr-slice-without-bounds-check.md"),
    },
    .{
        .id = "mutex-double-lock",
        .title = "`recv.lock()` twice without `recv.unlock()` in between — non-reentrant Mutex deadlocks (ReleaseFast) or asserts (Debug)",
        .body = @embedFile("rules/misc/mutex-double-lock.md"),
    },
};

/// Look up a rule by id.  Returns null on unknown id so callers can
/// surface a useful error rather than panicking.
pub fn lookup(id: []const u8) ?*const Rule {
    for (&all) |*r| {
        if (std.mem.eql(u8, r.id, id)) return r;
    }
    return null;
}

// ── Pattern-detector dispatch ───────────────────────────────

const Ast = std.zig.Ast;
const config_mod = @import("config.zig");
const problem_mod = @import("problem.zig");
const file_cache = @import("cache/file_cache.zig");

const Problem = problem_mod.Problem;
const Config = config_mod.Config;
const FileCache = file_cache.FileCache;

pub const Check = *const fn (
    std.mem.Allocator,
    *const Ast,
    *FileCache,
    *const Config,
    *std.ArrayListUnmanaged(Problem),
) anyerror!void;

pub const Detector = struct {
    id: []const u8,
    check: Check,
};

// ── Rule imports ─────────────────────────────────────────────

const aliased_heap_dupe_mod = @import("rules/heap/aliased_heap_dupe.zig");
const arraylist_element_ptr_mod = @import("rules/collection/arraylist_element_ptr.zig");
const arraylist_items_slice_mod = @import("rules/collection/arraylist_items_slice.zig");
const assert_on_untrusted_input_mod = @import("rules/misc/assert_on_untrusted_input.zig");
const asymmetric_field_free_mod = @import("rules/cleanup/asymmetric_field_free.zig");
const borrowed_slice_into_out_param_mod = @import("rules/borrow/borrowed_slice_into_out_param.zig");
const borrowed_slice_into_stack_buffer_returned_mod = @import("rules/borrow/borrowed_slice_into_stack_buffer_returned.zig");
const clobbered_by_struct_reset_mod = @import("rules/cleanup/clobbered_by_struct_reset.zig");
const dead_errdefer_in_result_fn_mod = @import("rules/errdefer/dead_errdefer_in_result_fn.zig");
const defer_and_errdefer_free_overlap_mod = @import("rules/errdefer/defer_and_errdefer_free_overlap.zig");
const deinit_order_violates_construction_dep_mod = @import("rules/cleanup/deinit_order_violates_construction_dep.zig");
const destroy_after_deinit_in_loop_mod = @import("rules/cleanup/destroy_after_deinit_in_loop.zig");
const duplicate_errdefer_mod = @import("rules/errdefer/duplicate_errdefer.zig");
const fd_write_after_close_mod = @import("rules/misc/fd_write_after_close.zig");
const free_then_try_realloc_mod = @import("rules/heap/free_then_try_realloc.zig");
const free_without_null_then_check_mod = @import("rules/heap/free_without_null_then_check.zig");
const hashmap_getptr_rehash_mod = @import("rules/collection/hashmap_getptr_rehash.zig");
const getorput_unguarded_value_read_mod = @import("rules/collection/getorput_unguarded_value_read.zig");
const hashmap_iter_mutation_mod = @import("rules/collection/hashmap_iter_mutation.zig");
const iterator_invalidation_mutation_mod = @import("rules/collection/iterator_invalidation_mutation.zig");
const thread_spawn_local_pointer_mod = @import("rules/misc/thread_spawn_local_pointer.zig");
const self_pointer_in_returned_value_mod = @import("rules/borrow/self_pointer_in_returned_value.zig");
const todo_panic_in_production_mod = @import("rules/misc/todo_panic_in_production.zig");
const memset_undef_after_len_truncation_mod = @import("rules/collection/memset_undef_after_len_truncation.zig");
const missing_deinit_on_composed_owner_mod = @import("rules/cleanup/missing_deinit_on_composed_owner.zig");
const missing_errdefer_between_tries_mod = @import("rules/errdefer/missing_errdefer_between_tries.zig");
const missing_errdefer_on_out_param_mod = @import("rules/errdefer/missing_errdefer_on_out_param.zig");
const move_out_without_restore_mod = @import("rules/cleanup/move_out_without_restore.zig");
const overwrite_without_deinit_mod = @import("rules/cleanup/overwrite_without_deinit.zig");
const owned_field_no_outer_cleanup_mod = @import("rules/cleanup/owned_field_no_outer_cleanup.zig");
const publish_then_touch_self_mod = @import("rules/misc/publish_then_touch_self.zig");
const realloc_byte_count_mod = @import("rules/heap/realloc_byte_count.zig");
const ref_before_ownership_transfer_mod = @import("rules/heap/ref_before_ownership_transfer.zig");
const opt_capture_ptr_after_field_clear_mod = @import("rules/heap/opt_capture_ptr_after_field_clear.zig");
const tagged_union_payload_early_exit_mod = @import("rules/misc/tagged_union_payload_early_exit.zig");
const union_payload_ptr_after_variant_change_mod = @import("rules/misc/union_payload_ptr_after_variant_change.zig");
const flag_reset_after_callback_mod = @import("rules/misc/flag_reset_after_callback.zig");
const slice_loop_reentrant_grow_mod = @import("rules/collection/slice_loop_reentrant_grow.zig");
const scope_push_pop_imbalance_mod = @import("rules/misc/scope_push_pop_imbalance.zig");
const exit_callback_cross_thread_mod = @import("rules/misc/exit_callback_cross_thread.zig");
const index_type_narrowing_wraparound_mod = @import("rules/misc/index_type_narrowing_wraparound.zig");
const ref_counted_copy_without_dupe_mod = @import("rules/misc/ref_counted_copy_without_dupe.zig");
const arraybuffer_slice_without_pin_mod = @import("rules/collection/arraybuffer_slice_without_pin.zig");
const optional_fallback_wrong_side_mod = @import("rules/misc/optional_fallback_wrong_side.zig");
const escape_skip_without_bounds_recheck_mod = @import("rules/misc/escape_skip_without_bounds_recheck.zig");
const recursive_parse_without_stack_check_mod = @import("rules/misc/recursive_parse_without_stack_check.zig");
const slice_from_fixed_offset_without_len_check_mod = @import("rules/misc/slice_from_fixed_offset_without_len_check.zig");
const negate_then_shift_without_minint_check_mod = @import("rules/misc/negate_then_shift_without_minint_check.zig");
const readint_unchecked_position_assignment_mod = @import("rules/misc/readint_unchecked_position_assignment.zig");
const arraylist_sentinel_write_without_capacity_mod = @import("rules/collection/arraylist_sentinel_write_without_capacity.zig");
const intfromfloat_without_clamp_mod = @import("rules/misc/intfromfloat_without_clamp.zig");
const int_sum_overflow_in_bounds_cmp_mod = @import("rules/misc/int_sum_overflow_in_bounds_cmp.zig");
const ptr_slice_without_bounds_check_mod = @import("rules/misc/ptr_slice_without_bounds_check.zig");
const mutex_double_lock_mod = @import("rules/misc/mutex_double_lock.zig");
const reset_skips_pooled_resource_release_mod = @import("rules/cleanup/reset_skips_pooled_resource_release.zig");
const return_borrowed_payload_mod = @import("rules/borrow/return_borrowed_payload.zig");
const self_undefined_after_destroy_mod = @import("rules/borrow/self_undefined_after_destroy.zig");
const sentinel_strip_free_size_mismatch_mod = @import("rules/heap/sentinel_strip_free_size_mismatch.zig");
const slice_of_arena_into_heap_mod = @import("rules/heap/slice_of_arena_into_heap.zig");
const stack_fallback_escape_mod = @import("rules/borrow/stack_fallback_escape.zig");
const tagged_union_retag_with_old_payload_read_mod = @import("rules/misc/tagged_union_retag_with_old_payload_read.zig");
const union_deinit_without_inert_reset_mod = @import("rules/cleanup/union_deinit_without_inert_reset.zig");
const unreleased_factory_handle_mod = @import("rules/cleanup/unreleased_factory_handle.zig");
const unreleased_refs_on_error_mod = @import("rules/errdefer/unreleased_refs_on_error.zig");

const escape_detectors = [_]Detector{
    .{ .id = "aliased-heap-dupe",                          .check = aliased_heap_dupe_mod.check },
    .{ .id = "clobbered-by-struct-reset",                  .check = clobbered_by_struct_reset_mod.check },
    .{ .id = "realloc-byte-count",                         .check = realloc_byte_count_mod.check },
    .{ .id = "asymmetric-field-free",                      .check = asymmetric_field_free_mod.check },
    .{ .id = "missing-errdefer-between-tries",             .check = missing_errdefer_between_tries_mod.check },
    .{ .id = "free-then-try-realloc",                      .check = free_then_try_realloc_mod.check },
    .{ .id = "destroy-after-deinit-in-loop",               .check = destroy_after_deinit_in_loop_mod.check },
    .{ .id = "dead-errdefer-in-result-fn",                 .check = dead_errdefer_in_result_fn_mod.check },
    .{ .id = "duplicate-errdefer",                         .check = duplicate_errdefer_mod.check },
    .{ .id = "overwrite-without-deinit",                   .check = overwrite_without_deinit_mod.check },
    .{ .id = "stack-fallback-escape",                      .check = stack_fallback_escape_mod.check },
    .{ .id = "unreleased-refs-on-error",                   .check = unreleased_refs_on_error_mod.check },
    .{ .id = "hashmap-getptr-rehash",                      .check = hashmap_getptr_rehash_mod.check },
    .{ .id = "arraylist-items-slice",                      .check = arraylist_items_slice_mod.check },
    .{ .id = "arraylist-element-ptr",                      .check = arraylist_element_ptr_mod.check },
    .{ .id = "fd-write-after-close",                       .check = fd_write_after_close_mod.check },
    .{ .id = "slice-of-arena-into-heap",                   .check = slice_of_arena_into_heap_mod.check },
    .{ .id = "free-without-null-then-check",               .check = free_without_null_then_check_mod.check },
    .{ .id = "tagged-union-retag-with-old-payload-read",   .check = tagged_union_retag_with_old_payload_read_mod.check },
    .{ .id = "union-deinit-without-inert-reset",           .check = union_deinit_without_inert_reset_mod.check },
    .{ .id = "self-undefined-after-destroy",               .check = self_undefined_after_destroy_mod.check },
    .{ .id = "missing-errdefer-on-out-param",              .check = missing_errdefer_on_out_param_mod.check },
    .{ .id = "reset-skips-pooled-resource-release",        .check = reset_skips_pooled_resource_release_mod.check },
    .{ .id = "return-borrowed-payload",                    .check = return_borrowed_payload_mod.check },
    .{ .id = "unreleased-factory-handle",                  .check = unreleased_factory_handle_mod.check },
    .{ .id = "memset-undef-after-len-truncation",          .check = memset_undef_after_len_truncation_mod.check },
    .{ .id = "publish-then-touch-self",                    .check = publish_then_touch_self_mod.check },
    .{ .id = "assert-on-untrusted-input",                  .check = assert_on_untrusted_input_mod.check },
    .{ .id = "missing-deinit-on-composed-owner",           .check = missing_deinit_on_composed_owner_mod.check },
    .{ .id = "owned-field-no-outer-cleanup",               .check = owned_field_no_outer_cleanup_mod.check },
    .{ .id = "borrowed-slice-into-out-param",              .check = borrowed_slice_into_out_param_mod.check },
    .{ .id = "defer-and-errdefer-free-overlap",            .check = defer_and_errdefer_free_overlap_mod.check },
    .{ .id = "sentinel-strip-free-size-mismatch",          .check = sentinel_strip_free_size_mismatch_mod.check },
    .{ .id = "move-out-without-restore",                   .check = move_out_without_restore_mod.check },
    .{ .id = "deinit-order-violates-construction-dep",     .check = deinit_order_violates_construction_dep_mod.check },
    .{ .id = "borrowed-slice-into-stack-buffer-returned",  .check = borrowed_slice_into_stack_buffer_returned_mod.check },
    .{ .id = "getorput-unguarded-value-read",              .check = getorput_unguarded_value_read_mod.check },
    .{ .id = "hashmap-iter-mutation",                      .check = hashmap_iter_mutation_mod.check },
    .{ .id = "iterator-invalidation-mutation",             .check = iterator_invalidation_mutation_mod.check },
    .{ .id = "thread-spawn-local-pointer",                 .check = thread_spawn_local_pointer_mod.check },
    .{ .id = "self-pointer-in-returned-value",             .check = self_pointer_in_returned_value_mod.check },
    .{ .id = "todo-panic-in-production",                   .check = todo_panic_in_production_mod.check },
    .{ .id = "ref-before-ownership-transfer",              .check = ref_before_ownership_transfer_mod.check },
    .{ .id = "opt-capture-ptr-after-field-clear",          .check = opt_capture_ptr_after_field_clear_mod.check },
    .{ .id = "tagged-union-payload-early-exit",            .check = tagged_union_payload_early_exit_mod.check },
    .{ .id = "union-payload-ptr-after-variant-change",     .check = union_payload_ptr_after_variant_change_mod.check },
    .{ .id = "flag-reset-after-callback",                  .check = flag_reset_after_callback_mod.check },
    .{ .id = "slice-loop-reentrant-grow",                  .check = slice_loop_reentrant_grow_mod.check },
    .{ .id = "scope-push-pop-imbalance",                   .check = scope_push_pop_imbalance_mod.check },
    .{ .id = "exit-callback-cross-thread",                 .check = exit_callback_cross_thread_mod.check },
    .{ .id = "index-type-narrowing-wraparound",            .check = index_type_narrowing_wraparound_mod.check },
    .{ .id = "ref-counted-copy-without-dupe",              .check = ref_counted_copy_without_dupe_mod.check },
    .{ .id = "arraybuffer-slice-without-pin",               .check = arraybuffer_slice_without_pin_mod.check },
    .{ .id = "optional-fallback-wrong-side",                .check = optional_fallback_wrong_side_mod.check },
    .{ .id = "escape-skip-without-bounds-recheck",          .check = escape_skip_without_bounds_recheck_mod.check },
    .{ .id = "recursive-parse-fn-without-stack-check",      .check = recursive_parse_without_stack_check_mod.check },
    .{ .id = "slice-from-fixed-offset-without-len-check",   .check = slice_from_fixed_offset_without_len_check_mod.check },
    .{ .id = "negate-then-shift-without-minint-check",      .check = negate_then_shift_without_minint_check_mod.check },
    .{ .id = "readint-unchecked-position-assignment",       .check = readint_unchecked_position_assignment_mod.check },
    .{ .id = "arraylist-sentinel-write-without-capacity",  .check = arraylist_sentinel_write_without_capacity_mod.check },
    .{ .id = "intfromfloat-without-clamp",                 .check = intfromfloat_without_clamp_mod.check },
    .{ .id = "int-sum-overflow-in-bounds-cmp",             .check = int_sum_overflow_in_bounds_cmp_mod.check },
    .{ .id = "ptr-slice-without-bounds-check",             .check = ptr_slice_without_bounds_check_mod.check },
    .{ .id = "mutex-double-lock",                          .check = mutex_double_lock_mod.check },
};

/// Dispatch all registered pattern detectors against `tree`.  `cache`
/// is amortized per-file shared state — rules borrow FileModel,
/// LocalBindings, FnSummary from it instead of building their own.
pub fn runEscape(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *FileCache,
    config: *const Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    for (escape_detectors) |rule| {
        try rule.check(gpa, tree, cache, config, problems);
    }
}

// ── Tests ──────────────────────────────────────────────────

test "catalog: every rule id is unique" {
    for (all, 0..) |a, i| {
        for (all[i + 1 ..]) |b| {
            try std.testing.expect(!std.mem.eql(u8, a.id, b.id));
        }
    }
}

test "catalog: every body is non-empty and starts with `# <id>`" {
    for (all) |r| {
        try std.testing.expect(r.body.len > 0);
        // Header line should match `# <id>` (markdown h1 with the
        // rule id).  Catches doc/catalog mismatches at build time.
        var header_buf: [128]u8 = undefined;
        const header = try std.fmt.bufPrint(&header_buf, "# {s}\n", .{r.id});
        try std.testing.expect(std.mem.startsWith(u8, r.body, header));
    }
}

test "catalog: lookup hits and misses" {
    try std.testing.expect(lookup("heap-use-after-free") != null);
    try std.testing.expect(lookup("not-a-real-rule") == null);
}

test "registry: every detector id is unique" {
    var seen: std.StringHashMap(void) = .init(std.testing.allocator);
    defer seen.deinit();
    for (escape_detectors) |rule| {
        const gop = try seen.getOrPut(rule.id);
        try std.testing.expect(!gop.found_existing);
    }
}

test "registry: ids are kebab-case (lowercase + hyphen)" {
    for (escape_detectors) |rule| {
        for (rule.id) |c| {
            try std.testing.expect(c == '-' or (c >= 'a' and c <= 'z'));
        }
    }
}

test "registry: pull in every rule module so inline tests run" {
    _ = aliased_heap_dupe_mod;
    _ = arraylist_element_ptr_mod;
    _ = arraylist_items_slice_mod;
    _ = assert_on_untrusted_input_mod;
    _ = asymmetric_field_free_mod;
    _ = borrowed_slice_into_out_param_mod;
    _ = borrowed_slice_into_stack_buffer_returned_mod;
    _ = clobbered_by_struct_reset_mod;
    _ = dead_errdefer_in_result_fn_mod;
    _ = defer_and_errdefer_free_overlap_mod;
    _ = deinit_order_violates_construction_dep_mod;
    _ = destroy_after_deinit_in_loop_mod;
    _ = duplicate_errdefer_mod;
    _ = getorput_unguarded_value_read_mod;
    _ = hashmap_iter_mutation_mod;
    _ = iterator_invalidation_mutation_mod;
    _ = thread_spawn_local_pointer_mod;
    _ = self_pointer_in_returned_value_mod;
    _ = todo_panic_in_production_mod;
    _ = fd_write_after_close_mod;
    _ = free_then_try_realloc_mod;
    _ = free_without_null_then_check_mod;
    _ = hashmap_getptr_rehash_mod;
    _ = memset_undef_after_len_truncation_mod;
    _ = missing_deinit_on_composed_owner_mod;
    _ = missing_errdefer_between_tries_mod;
    _ = missing_errdefer_on_out_param_mod;
    _ = move_out_without_restore_mod;
    _ = overwrite_without_deinit_mod;
    _ = owned_field_no_outer_cleanup_mod;
    _ = publish_then_touch_self_mod;
    _ = realloc_byte_count_mod;
    _ = reset_skips_pooled_resource_release_mod;
    _ = return_borrowed_payload_mod;
    _ = self_undefined_after_destroy_mod;
    _ = sentinel_strip_free_size_mismatch_mod;
    _ = slice_of_arena_into_heap_mod;
    _ = stack_fallback_escape_mod;
    _ = tagged_union_retag_with_old_payload_read_mod;
    _ = union_deinit_without_inert_reset_mod;
    _ = unreleased_factory_handle_mod;
    _ = unreleased_refs_on_error_mod;
    _ = ref_before_ownership_transfer_mod;
    _ = opt_capture_ptr_after_field_clear_mod;
    _ = tagged_union_payload_early_exit_mod;
    _ = union_payload_ptr_after_variant_change_mod;
    _ = flag_reset_after_callback_mod;
    _ = slice_loop_reentrant_grow_mod;
    _ = scope_push_pop_imbalance_mod;
    _ = exit_callback_cross_thread_mod;
    _ = index_type_narrowing_wraparound_mod;
    _ = ref_counted_copy_without_dupe_mod;
    _ = arraybuffer_slice_without_pin_mod;
    _ = optional_fallback_wrong_side_mod;
    _ = escape_skip_without_bounds_recheck_mod;
    _ = recursive_parse_without_stack_check_mod;
    _ = slice_from_fixed_offset_without_len_check_mod;
    _ = negate_then_shift_without_minint_check_mod;
    _ = readint_unchecked_position_assignment_mod;
    _ = arraylist_sentinel_write_without_capacity_mod;
    _ = intfromfloat_without_clamp_mod;
    _ = int_sum_overflow_in_bounds_cmp_mod;
    _ = ptr_slice_without_bounds_check_mod;
    _ = mutex_double_lock_mod;
}
