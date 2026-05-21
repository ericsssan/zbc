//! Project-tunable knobs.  Small by design — zbc is a focused
//! arena-escape checker for Zig source.  Two pattern lists let
//! projects declare what counts as arena creation/destruction in
//! their codebase (defaults match std.heap.ArenaAllocator).

const std = @import("std");

pub const Config = struct {
    /// Source-text substrings that classifyExpr treats as
    /// "this call mints a fresh arena."  First match wins.
    /// Substring match (not token-aware) — order from specific to
    /// least specific if you customize.
    arena_init_patterns: []const []const u8 = &.{
        "ArenaAllocator.init",
    },

    /// Source-text substrings for "this call kills the receiver
    /// arena."  Detected in lowerCallStmt — matching call shapes
    /// emit `.arena_kill` against the receiver local.
    arena_kill_patterns: []const []const u8 = &.{
        ".deinit(",
    },

    /// Source-text substrings for "this call returns a heap
    /// allocation."  Defaults cover std.mem.Allocator's surface.
    /// Matched as substrings of the full call expression.
    heap_alloc_patterns: []const []const u8 = &.{
        ".alloc(",
        ".allocSentinel(",
        ".create(",
        ".dupe(",
        ".dupeZ(",
        ".allocPrint(",
        ".allocPrintZ(",
    },

    /// Source-text substrings for "this call frees its first arg."
    /// The freed pointer is extracted from the call's args[0].
    heap_free_patterns: []const []const u8 = &.{
        ".free(",
        ".destroy(",
    },

    /// Which invariants to enforce.  zbc currently has exactly one
    /// — arena_escape (slice borrowed from function-local arena
    /// must not escape).  Kept as a list so future generic
    /// invariants can be added without breaking the CLI surface.
    enabled: []const Invariant = &all_invariants,
};

/// Invariants zbc enforces.  All generic — no language-domain
/// assumptions about parsers, ASTs, or any project-specific
/// vocabulary.
pub const Invariant = enum {
    /// A slice borrowed from a function-local arena must not be
    /// returned past the arena's death.  Catches the common
    /// "return a slice from per-call arena" mistake.
    arena_escape,
    /// A pointer or slice into a function-local stack variable must
    /// not be returned — the storage dies with the frame.
    stack_escape,
    /// A value initialized to `undefined` and never reassigned must
    /// not be returned (caller would receive garbage).
    use_undefined,
    /// A heap allocation must not be freed twice on any path.
    heap_double_free,
    /// A heap pointer must not be read or returned after it has
    /// been freed.
    heap_use_after_free,
    /// A value borrowed from an arena must not be read after the
    /// arena is deinit'd.  Complements arena_escape (which catches
    /// the special case of leaking the borrow past return).
    arena_use_after_kill,
    /// A heap allocation must be freed with the same allocator
    /// that produced it.  Catches the oven-sh/bun#29840 class:
    /// `mimalloc_arena.alloc(...)` then `default.free(...)` (UB
    /// under any reasonable allocator implementation).
    allocator_mismatch,
    /// Calling a destructor (`destroy` / `deinit` / etc.) on an
    /// interior pointer into a container's storage is UB under
    /// typical allocators.  Catches the oven-sh/bun#30166 class:
    /// `for (entries.items) |*r| r.destroy();`.
    interior_pointer_destroy,
    /// A type with a heap-creator method (`<x>.create(Self)`) has
    /// a destructor (finalize / deinit / destroy) that doesn't
    /// free `self` — every instance leaks the heap descriptor.
    /// Catches oven-sh/bun#29840 class: `ResolveMessage.create` allocates
    /// self via `allocator.create(...)` but `finalize()` never
    /// calls `allocator.destroy(this)`.
    heap_leak,
    /// An assignment to long-lived storage (`x.* = ...` or
    /// `obj.field = ...`) whose RHS is an anonymous struct literal
    /// `.{ .tag = <expr> }` where `<expr>` contains an early-exit
    /// (`try ...` or `catch return ...` / `catch |...| { ... return; ... }`).
    /// Zig writes the union tag to the result location BEFORE
    /// evaluating the payload, so on the error path the LHS is
    /// left with the new tag and the old/garbage payload bytes — a
    /// later read (often via an `errdefer this.deinit()`) sees a
    /// wild pointer.  Catches oven-sh/bun#29422 class.
    partial_union_write,
    /// A "dupe" function returns `T` by value via a bitwise copy
    /// (`var dup = this.*; return dup;`), and T has a heap-owning
    /// field signalled by an `<X>_allocated: bool` sibling — but
    /// the dupe doesn't either clear `<X>_allocated` or re-allocate
    /// `<X>` independently.  Both the source and the dupe now hold
    /// the same heap pointer with `<X>_allocated == true`, so the
    /// later frees from each side collide (UAF, then double-free).
    /// Catches oven-sh/bun#29910 class: `Blob.dupeWithContentType`.
    aliased_heap_dupe,
    /// A heap-owning field is assigned (`this.<X> = <expr>;`) and
    /// then `this.*` is overwritten with a struct literal that
    /// does NOT include `.<X>`, so `<X>` silently falls back to
    /// its declared default (usually `null` / `&.{}`).  The prior
    /// heap pointer is unreachable and never freed by `deinit()`
    /// (which checks the now-default value).  Catches oven-sh/bun#29854
    /// class: `PathWatcher.init` clobbered `this.resolved_path`.
    clobbered_by_struct_reset,
    /// A call to `<allocator>.realloc(slice, <expr> * @sizeOf(T))`
    /// — the new-length argument multiplies by `@sizeOf(T)` as if
    /// it were a byte count, but Zig's `Allocator.realloc` takes
    /// an ELEMENT count.  The allocation grows by `@sizeOf(T)×`
    /// the intended size on every call.  Catches oven-sh/bun#29452 class:
    /// `SmallList.tryGrow` over-allocated.
    realloc_byte_count,
    /// A type's destructor (`deinit` / `finalize` / `destroy`)
    /// mentions some same-typed sibling fields but omits others.
    /// E.g. fields `query_string_map: ?QueryStringMap` and
    /// `param_map: ?QueryStringMap` — destructor handles the
    /// first but forgets the second.  Catches oven-sh/bun#29853 class:
    /// `MatchedRoute.deinit` forgot to free `param_map`.
    asymmetric_field_free,
    /// `const X = try <Type>.<method>(...);` where `<Type>` has a
    /// `deinit` method, then a subsequent `try` in the same scope
    /// with NO `errdefer X.deinit();` between.  If the second
    /// `try` throws, X leaks (its deinit isn't reached).  Catches
    /// oven-sh/bun#30169 class: `node_fs` Symlink/Link/Rename.fromJS where
    /// `old_path` was leaked when `new_path = try PathLike.fromJS(...)`
    /// errored.
    missing_errdefer_between_tries,
    /// `<allocator>.free(X); X = try <allocator>.alloc(...);` —
    /// after the free, X points at freed memory.  If the `try`'s
    /// alloc fails, the function returns the error and `X` is
    /// still that dangling pointer — a later `deinit` (which
    /// expects an owned slice) frees it again, double-freeing /
    /// using freed memory.  Fix is to set `X = &.{};` (or
    /// `undefined`) between the free and the fallible realloc.
    /// Catches oven-sh/bun#29968 class: MySQLConnection.handleResultSet
    /// reallocating `statement.columns` without clearing first.
    free_then_try_realloc,
    /// A destructor (`deinit` / `finalize` / `destroy`) loops over
    /// `<list>.items` calling `<h>.deinit()` per item but never
    /// `<allocator>.destroy(<h>)` (or `.free(<h>)`).  When the
    /// list's element type is a heap-allocated pointer (e.g.
    /// `std.ArrayList...(*Handler)` with items minted via
    /// `allocator.create(Handler)`), the per-item destructor
    /// reclaims the item's fields but not its heap descriptor —
    /// every list item leaks its allocation.  Catches oven-sh/bun#29879
    /// class: `LOLHTMLContext.deinit` looped handlers and called
    /// `handler.deinit()` but never `allocator.destroy(handler)`.
    destroy_after_deinit_in_loop,
    /// A fn whose return type is a parameterized tagged union
    /// (`Result(T)`, `Maybe(T)`, …) — NOT a Zig error union
    /// (`!T`) — contains an `errdefer` in its body.  Zig's
    /// `errdefer` only runs on Zig error returns (`return
    /// error.X`); a `return .{ .err = e }` is a normal return,
    /// so the errdefer never fires.  Any cleanup it was meant
    /// to do silently leaks.  Catches oven-sh/bun#27706 class: CSS
    /// parsers with `Result(T)` return type and dead errdefer
    /// blocks.
    dead_errdefer_in_result_fn,
    /// Two `errdefer <X>.<cleanup>();` statements register the
    /// same cleanup against the same receiver in one fn body.  On
    /// the error path both fire — the cleanup runs twice and the
    /// second call hits its assert / double-frees / corrupts
    /// state.  Catches tigerbeetle/tigerbeetle#2700 class:
    /// `Command.init` registered `errdefer command.io.deinit()`
    /// twice; second `IO.deinit()` hit
    /// `assert(self.fd >= 0)` in `IoUring.deinit`.
    duplicate_errdefer,
    /// `<this>.<field> = <RHS>;` where `<field>`'s declared type
    /// has a `deinit` method — but no `<this>.<field>.deinit();`
    /// (or `.deref()` / `.free()`) appears in the preceding few
    /// statements.  Each reassignment leaks the prior allocation.
    /// Single-field counterpart to `clobbered-by-struct-reset`
    /// (whole-struct overwrite).  Catches oven-sh/bun#28633 /
    /// oven-sh/bun#29864 class: protocol decoders and re-execute
    /// paths overwriting heap-owning fields without cleanup.
    overwrite_without_deinit,
    /// `var <SF> = std.heap.stackFallback(N, <alloc>);` produces an
    /// allocator whose small allocations land in the *caller's*
    /// stack frame.  When a container built on `<SF>.get()` calls
    /// `.toOwnedSlice()` / `.toOwnedSliceSentinel()` / similar and
    /// the resulting slice escapes the function (return, out-param
    /// write, store in a non-local struct), the pointer dangles
    /// once the frame dies — intermittent UAF whenever the
    /// allocation stays under the fallback threshold.  Catches
    /// ghostty-org/ghostty#9885 class; same shape as
    /// ziglang/zig#16344.
    stack_fallback_escape,
    /// A loop body contains `<obj>.<addref>()` calls (where addref ∈
    /// {`reference`, `retain`, `addRef`, `addref`}) acquiring
    /// refcounted references, and the enclosing fn has a later `try`
    /// with no `errdefer` containing a release-class method call
    /// (`release` / `deref` / `unref` / `removeRef`).  On the try's
    /// error path the references taken in the loop leak.  Catches
    /// the `hexops/mach` sysgpu/vulkan.zig PipelineLayout.init class:
    /// `for (...) |bgl| bgl.manager.reference();` then `try
    /// vkd.createPipelineLayout(...);` — no errdefer releases the
    /// references on vulkan-create failure.
    unreleased_refs_on_error,
    /// `const <X> = <map>.getPtr(...);` (or `getOrPut`,
    /// `getOrPutValue`, `getOrPutAssumeCapacity`,
    /// `getOrPutAdapted`) borrows a pointer into the map's internal
    /// storage.  A subsequent `<map>.<mutate>(...)` on the SAME
    /// receiver — where mutate ∈ {`put`, `putAssumeCapacity`,
    /// `putNoClobber`, `putNoClobberAssumeCapacity`, `remove`,
    /// `removeByPtr`, `fetchPut`, `fetchRemove`, `swapRemove`} — may
    /// rehash the table and invalidate `<X>`.  A later read of
    /// `<X>` is a UAF against table storage.  Zig std's HashMap
    /// docs explicitly call out that pointers returned by `getPtr`
    /// / `getOrPut.value_ptr` are valid only until the next
    /// capacity-modifying call.
    hashmap_getptr_rehash,
    /// `const <X> = <list>.items;` borrows a slice over the list's
    /// heap-backed storage.  A subsequent `<list>.<mutate>(...)` on
    /// the SAME receiver (where mutate ∈ {`append`, `appendSlice`,
    /// `appendNTimes`, `insert`, `insertSlice`, `addOne`,
    /// `addManyAsSlice`, `addManyAsArray`, `resize`, `clearAndFree`,
    /// `deinit`}) may reallocate the backing storage and invalidate
    /// `<X>.ptr` — a later read/write through `<X>` is a UAF
    /// against list storage.  Sibling of [[hashmap-getptr-rehash]];
    /// `*AssumeCapacity` variants are deliberately excluded (no
    /// realloc by contract).
    arraylist_items_slice,
    /// `const|var <X> = try <dir>.<opener>(...);` binds an OS file
    /// handle; `<X>.close();` invalidates it; any subsequent use of
    /// `<X>` (method call or field access) reads/writes through a
    /// dangling fd.  On POSIX the closed fd may be reassigned by
    /// the kernel before the stale use lands, silently routing the
    /// write to an unrelated file.  Openers: createFile / openFile
    /// / openDir / open / openat / accept / socket (and their `Z`
    /// variants).  Skips defer/errdefer close (fires at scope exit,
    /// after every other use) and close inside diverging branches
    /// (catch/if bodies).
    fd_write_after_close,
    /// A slice allocated through a function-local
    /// `std.heap.ArenaAllocator` is passed as data to a container
    /// method (`append` / `appendSlice` / `put` / etc.) whose
    /// allocator argument is NOT the arena's allocator — when the
    /// arena dies at fn exit, the container holds a dangling
    /// slice.  Complements `arena_escape` (escape via return) and
    /// `arena_use_after_kill` (read after deinit) by catching the
    /// third escape path: STORE into a longer-lived container
    /// during the arena's lifetime.
    slice_of_arena_into_heap,
    /// `<allocator>.destroy(<recv>.<field>);` / `.free(<recv>.<field>);`
    /// in a NON-destructor fn without a subsequent
    /// `<recv>.<field> = null;` (or `= &.{}`, `= .empty`, `= ...new`).
    /// The freed slot now holds a dangling pointer; a later
    /// `if (<recv>.<field>) |h| use(h);` passes the optional null-
    /// check and UAFs, or the struct's own `deinit` re-frees the
    /// dangling slot.  Catches oven-sh/bun#30148 / #30176 / #29983 /
    /// #29988 class.
    free_without_null_then_check,
    /// `<path> = .{ .<NewTag> = .{ ... <path>.<OldTag>... ... } };`
    /// — reading the old tag's payload while assigning a new tag to
    /// the same union.  Under Zig's x86_64 self-hosted backend
    /// the active-tag flip happens BEFORE the RHS evaluates, so the
    /// old payload read may see undefined / garbage.  LLVM hides
    /// this on aarch64.  Catches tigerbeetle/tigerbeetle#3317 +
    /// #2200 class (same file `src/lsm/scan_tree.zig`, same shape,
    /// 14 months apart).
    tagged_union_retag_with_old_payload_read,
    /// A `switch (<recv>.<field>)` arm `.<Tag> => |*v| <body>`
    /// where `<body>` calls a cleanup method on the payload
    /// (`v.deinit()` / `v.<sub>.deinit()` / `.free()` / `.release()`
    /// / `.deref()` / `.destroy()` / `.close()`) but does NOT
    /// retag `<recv>.<field>` to an inert variant.  In a fn named
    /// `reset` / `clear` / `end` (idempotent by convention) the
    /// next call fires the same arm and double-frees.  Catches
    /// ghostty-org/ghostty#2257 + #8307 class.
    union_deinit_without_inert_reset,
    /// `<alloc>.destroy(<X>);` immediately followed by `<X>.* = ...`
    /// or `<X>.<field> = ...` — the write hits freed memory.  The
    /// canonical TigerStyle invariant is overwrite-THEN-free:
    /// `<X>.* = undefined; <alloc>.destroy(<X>);` — this rule
    /// catches the inversion.  Catches tigerbeetle/tigerbeetle#2687
    /// class.
    self_undefined_after_destroy,
    /// Multi-step in-place struct-builder:
    /// `try <out>.<field>.<acquire>(...)` (where `<out>` ∈
    /// {`result`, `out`, `r`} and `<acquire>` ∈
    /// {`ensureTotalCapacity`, `init`, `append`, ...}) populates
    /// `<out>.<field>` but a later `try` runs with no `errdefer
    /// <out>.<field>.deinit(...)` registered.  Catches
    /// ghostty-org/ghostty#10401 class — distinct from existing
    /// `missing-errdefer-between-tries` which covers the binding-
    /// and-leak `const X = try Type.method()` shape.
    missing_errdefer_on_out_param,
    /// A struct's `deinit` releases owned pool / sub-allocator
    /// slots (`<obj>.<cleanup>(...)` where cleanup ∈ {`release`,
    /// `free`, `destroy`, `close`, `deinit`, `unref`, `deref`}),
    /// but the sibling `reset` method doesn't.  State is logically
    /// "freed" after `reset` but the slots are still held.
    /// Catches tigerbeetle/tigerbeetle#3436 + #1734 class.
    reset_skips_pooled_resource_release,
};

pub const all_invariants: [32]Invariant = .{
    .arena_escape,
    .stack_escape,
    .use_undefined,
    .heap_double_free,
    .heap_use_after_free,
    .arena_use_after_kill,
    .allocator_mismatch,
    .interior_pointer_destroy,
    .heap_leak,
    .partial_union_write,
    .aliased_heap_dupe,
    .clobbered_by_struct_reset,
    .realloc_byte_count,
    .asymmetric_field_free,
    .missing_errdefer_between_tries,
    .free_then_try_realloc,
    .destroy_after_deinit_in_loop,
    .dead_errdefer_in_result_fn,
    .duplicate_errdefer,
    .overwrite_without_deinit,
    .stack_fallback_escape,
    .unreleased_refs_on_error,
    .hashmap_getptr_rehash,
    .arraylist_items_slice,
    .fd_write_after_close,
    .slice_of_arena_into_heap,
    .free_without_null_then_check,
    .tagged_union_retag_with_old_payload_read,
    .union_deinit_without_inert_reset,
    .self_undefined_after_destroy,
    .missing_errdefer_on_out_param,
    .reset_skips_pooled_resource_release,
};

pub const Default: Config = .{};

/// True iff `config.enabled` contains `inv`.
pub fn isEnabled(config: *const Config, inv: Invariant) bool {
    for (config.enabled) |e| {
        if (e == inv) return true;
    }
    return false;
}

/// Map a CLI-style name to its Invariant tag.  Returns null on
/// unknown names so callers can surface a useful error message
/// rather than silently ignoring typos.
pub fn invariantFromName(name: []const u8) ?Invariant {
    inline for (@typeInfo(Invariant).@"enum".fields) |f| {
        if (std.mem.eql(u8, name, f.name)) return @enumFromInt(f.value);
    }
    return null;
}

// ── Tests ──────────────────────────────────────────────────

test "Default config defaults" {
    try std.testing.expectEqualStrings("ArenaAllocator.init", Default.arena_init_patterns[0]);
    try std.testing.expectEqualStrings(".deinit(", Default.arena_kill_patterns[0]);
}

test "invariantFromName round-trips every variant" {
    inline for (@typeInfo(Invariant).@"enum".fields) |f| {
        const got = invariantFromName(f.name).?;
        try std.testing.expectEqual(@as(Invariant, @enumFromInt(f.value)), got);
    }
}

test "invariantFromName returns null on unknown" {
    try std.testing.expectEqual(@as(?Invariant, null), invariantFromName("not_an_invariant"));
}
