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
    /// `const <X> = &<list>.items[<idx>];` borrows a pointer to a
    /// specific element.  A subsequent grow call on the SAME list
    /// (append/insert/resize/etc.) may reallocate the backing buffer —
    /// `<X>` then dangles.  Sibling of [[arraylist-items-slice]];
    /// element-pointer variant.  oven-sh/bun#29483.
    arraylist_element_ptr,
    /// `for (<list>.items) |...| { ... <list>.<mutate>(...); ... }`
    /// — the loop iterates over a snapshot of `.items` while the
    /// body calls a method on the SAME list that reallocates or
    /// reorders the backing storage (append/resize/insert/
    /// swapRemove/etc., plus hashmap put/remove that rehash).
    /// The loop's slice borrow may dangle, skip elements, or
    /// double-visit elements.  Sibling of [[arraylist-items-slice]]
    /// which fires on `const X = list.items;` + later mutate +
    /// later use of X; this rule fires on the loop SHAPE directly.
    iterator_invalidation_mutation,
    /// `Thread.spawn(.{}, fn, .{ &<local> })` /
    /// `<pool>.spawn(fn, .{ &<local> })` — passing the address of
    /// a function-LOCAL into a spawned thread.  The thread out-
    /// lives the spawning fn's frame, so the local pointer dangles
    /// once the fn returns.  Skips `&<param>` (caller-supplied
    /// pointer, not a stack-frame leak from this frame) and
    /// `&<heap-local>` (when the local was heap-allocated).
    thread_spawn_local_pointer,
    /// `<local>.<field> = &<local>;` then `return <local>;` — the
    /// self-referential struct is COPIED on return; the field
    /// still holds the original stack address, which is invalid
    /// both during and after the copy.  Catches the "self-pointer
    /// in returned-by-value struct" footgun common when porting
    /// C / Rust code that uses intrusive self-references.
    self_pointer_in_returned_value,
    /// `@panic("TODO ...")` / `@panic("unimplemented")` /
    /// `@panic("FIXME ...")` / etc. left in code that may run
    /// in release builds.  TODO-panics are a development
    /// scaffold; reaching them in production crashes the user's
    /// process.  Either return an explicit error or gate the
    /// branch out at compile time.
    todo_panic_in_production,
    /// `const gop = try map.getOrPut(key);` followed by
    /// `gop.value_ptr.*` used as a READ without a prior check of
    /// `gop.found_existing`.  When `found_existing == false` the map
    /// inserted a new slot; `value_ptr.*` is uninitialised and reading
    /// it is undefined behaviour.  Write-only access (`gop.value_ptr.*
    /// = value;`) is safe without the check.
    getorput_unguarded_value_read,
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
    /// `return switch (<expr>) { .<Tag1> => |v| v, .<Tag2> => |v|
    /// try alloc.dupe(u8, v), ... };` — sibling-arm asymmetry.
    /// One arm clones / allocates the payload to give the caller
    /// ownership; the other arm returns the captured payload bare,
    /// which is a slice/pointer borrowed from the caller's input.
    /// Catches ghostty-org/ghostty#8358 + #7711 class.
    return_borrowed_payload,
    /// GPU/refcounted-factory leak — `const <X> = [try]
    /// <device>.<create-method>(...)` returns a refcounted handle
    /// with initial refcount=1, but the fn body has no `defer
    /// <X>.release()` AND the handle isn't returned or stored as
    /// a struct field.  One ref leaks per call.  Catches hexops/mach
    /// examples (custom-renderer, glyphs/App.zig).  Distinct from
    /// `unreleased-refs-on-error` which is about loop-side addref
    /// without paired release.
    unreleased_factory_handle,
    /// `<X>.<field>.len = NEW;` followed by `@memset(<X>.<field>...,
    /// undefined);` in the same scope — the memset slices the
    /// ALREADY-TRUNCATED items so the range is empty and the memset
    /// is a no-op.  The freed-but-retained capacity keeps its old
    /// bytes, defeating Zig's `undefined` use-after-shrink safety.
    /// Catches ziglang/zig#25810 + #25832 class.
    memset_undef_after_len_truncation,
    /// `<chain>.<publish-method>(this);` (or `(self)`) where the
    /// chain or method suggests concurrent / cross-thread dispatch
    /// (`queue.push`, `thread_pool.dispatch`, `enqueueTaskConcurrent`,
    /// etc.), followed by any further use of `this`/`self` in the
    /// same scope.  The consumer thread may have freed `this`
    /// before the access lands → cross-thread UAF.  Catches
    /// oven-sh/bun#29128 + #31177 + #30185 class.
    publish_then_touch_self,
    /// `assert(<expr>)` in a parser/decoder fn where `<expr>`
    /// references untrusted-input parameters (`buffer`, `bytes`,
    /// `data`, `message`, `block`, ...).  Crafted input panics the
    /// process.  TigerStyle: asserts are for INTERNAL invariants;
    /// external input requires `if (!<cond>) return error.Invalid;`.
    /// Catches tigerbeetle/tigerbeetle#3709 + #3726 + #2980 class.
    assert_on_untrusted_input,
    /// Outer struct's `deinit` doesn't call `<self>.<field>.deinit(...)`
    /// for a field whose type (same file) ALSO exposes a deinit.
    /// The inner's owned non-memory resources (file handles,
    /// sockets, refs, mmaps) leak.  Catches ziglang/zig#22683
    /// class (StackIterator forgot to call ma.deinit → /proc fd
    /// leak); related to ziglang/zig#20192 and #18651.
    missing_deinit_on_composed_owner,
    /// Outer struct has a value-typed field whose type (same file)
    /// exposes a cleanup method (deinit/close/destroy/free/stop/
    /// finalize/dispose) — but the outer struct exposes NO cleanup
    /// method of its own.  Users who treat `Outer` as a plain value
    /// silently leak the inner's owned resource on drop.  The
    /// complement to `missing-deinit-on-composed-owner`: that rule
    /// fires when deinit EXISTS but is incomplete; this one fires
    /// when deinit is missing entirely.
    owned_field_no_outer_cleanup,
    /// `defer <X>.deinit()` (or `defer <alloc>.free(<X>)`) and a
    /// later write `<out>.* = ...<X>...` into a pointer-typed
    /// fn parameter — the out-param holds a dangling slice once
    /// the defer fires on return.  Catches oven-sh/bun#30151 +
    /// #30223 + #25563 class.
    borrowed_slice_into_out_param,
    /// `defer <alloc>.free(<X>);` + `errdefer { ... <lhs> = <X>; }`
    /// (resurrects X into a field) + a subsequent `try` — on
    /// error, errdefer fires (frees NEW, restores OLD into the
    /// field), then defer fires (frees OLD).  The field is now a
    /// dangling pointer.  Catches ghostty-org/ghostty#8249
    /// (`Atlas.grow`).
    defer_and_errdefer_free_overlap,
    /// `<alloc>.free(<X>.ptr[0..<X>.len])` (or `.ptr.?[0..len]`)
    /// hand-rolls a non-sentinel slice from a many-item-pointer.
    /// If `<X>` is `[:0]const u8` or another sentinel-terminated
    /// slice, the underlying allocation is len+1 bytes — the
    /// allocator's free-size check trips ("Allocation size N+1
    /// does not match free size N").  Catches
    /// ghostty-org/ghostty#8886.
    sentinel_strip_free_size_mismatch,
    /// `var <X> = <OBJ>.toArrayList(...)` (or similar move-out
    /// method that clears OBJ's state) + fallible op on <X> +
    /// no `defer <OBJ>.setArrayList(<X>);` between.  On error,
    /// X is dropped with partial allocation and OBJ is left
    /// holding cleared/stale state.  Catches ziglang/zig#24452
    /// class (`Io.Writer.Allocating.toOwnedSlice*`).
    move_out_without_restore,
    /// In a fn body, `<A> = <T>.init(&<B>, ...)` creates a dep
    /// edge B→A.  Later `<B>.deinit()` runs BEFORE `<A>.deinit()`
    /// — A's deinit may dereference its borrowed pointer to B,
    /// which is already torn down.  Catches
    /// tigerbeetle/tigerbeetle#3732 (manifest_log_fuzz).
    deinit_order_violates_construction_dep,
    /// A stack-local `var <buf>: [N]<T> = undefined;` is passed
    /// to an aliasing parser (`SemanticVersion.parse`, etc.),
    /// and the returned struct (whose sub-slice fields alias
    /// the buffer) is then `return`-ed.  The caller receives a
    /// struct whose `.pre`/`.build`-style fields point at the
    /// now-dead stack buffer.  Catches ziglang/zig#25713 class.
    borrowed_slice_into_stack_buffer_returned,
    /// `var iter = <map>.<iter-method>();` followed by
    /// `while (iter.next()) |...| { ... <map>.<mutate>(...) ... }` —
    /// modifying a HashMap (put / remove / clear / etc.) while
    /// iterating it via `iterator()` / `keyIterator()` /
    /// `valueIterator()` invalidates the iterator's internal cursor.
    /// Subsequent calls to `iter.next()` have undefined behaviour.
    hashmap_iter_mutation,
    /// `<recv>.<addref>()` (addref ∈ ref/retain/reference/addRef/
    /// addref) immediately before `init(<recv>, …)` — the caller bumps
    /// the refcount by 1, but the init-style callee takes ownership and
    /// decrements exactly once.  The extra ref is never balanced and
    /// the object leaks.  Fix: remove the addref, OR keep it and add a
    /// paired `defer <recv>.deref()`.  Catches oven-sh/bun#30137 class.
    ref_before_ownership_transfer,
    /// Inside `if (<recv>.<field>) |*<cap>| { … }`, a local `<ptr>`
    /// is derived from `<cap>` (mutable pointer to the optional
    /// payload).  The same block then contains an inline assignment
    /// `<recv>.<field> = …` (null or other) that destroys the storage
    /// `<ptr>` was pointing into.  Any subsequent use of `<ptr>` is a
    /// UAF.  Inline-clear variant of oven-sh/bun#29979.  The callee-
    /// clear variant is covered by heap-use-after-free (CFG-level).
    opt_capture_ptr_after_field_clear,
    /// Single-field tagged-union literal assignment where the payload
    /// expression contains `try`.  Under Zig's x86_64 self-hosted
    /// backend (post-0.15) the tag flip happens BEFORE the payload
    /// evaluates; if `try` propagates an error the tag is written
    /// but the payload remains from the previous variant.
    /// oven-sh/bun#29422.
    tagged_union_payload_early_exit,
    /// `const <ptr> = &<recv>.<field1>.<field2>` followed by
    /// `<recv>.<field1> = …` (variant change) followed by use of
    /// `<ptr>`.  After the variant change the payload storage `<ptr>`
    /// points into is repurposed; any use is a UAF.
    /// oven-sh/bun#29977.
    union_payload_ptr_after_variant_change,
    /// `<recv>.<field> = true` → function call → `<recv>.<field> =
    /// false`, where `<field>` contains `in_progress`.  If the
    /// function triggers re-entrant code that sets the flag back to
    /// `true`, the post-call `false` clobbers that new state.
    /// oven-sh/bun#29899.
    flag_reset_after_callback,
    /// `for (<recv>.items) |…| { … call() … }` where `call`
    /// transitively invokes an ArrayList-grow method.  The loop's
    /// implicit slice pointer is invalidated by the reallocation.
    /// oven-sh/bun#29981, #29483.
    slice_loop_reentrant_grow,
    /// `<recv>.pushScope(…)` (or enterScope/pushContext/etc.) without
    /// a matching `defer <recv>.popScope()` (or similar pop method),
    /// when the fn body has at least one early `return`.  Early returns
    /// exit without popping, leaving the scope stack one level too deep
    /// and causing underflows on subsequent calls.  Catches
    /// oven-sh/bun#31239 / #31340 / #31231 class.
    scope_push_pop_imbalance,
    /// A function registered as an at-exit or cross-thread callback
    /// (via add_exit_callback / addExitCallback / onExit / atexit /
    /// etc.) accesses mutable state via `self.` field accesses without
    /// a `is_main_thread()` / `isMainThread()` / `isCLIThread()` guard.
    /// When process exit is triggered from a worker thread, the callback
    /// runs there and races with main-thread teardown.
    /// Catches oven-sh/bun#31376 class.
    exit_callback_cross_thread,
    /// `var NAME: iN = EXPR` where N ∈ {8, 16, 32} (a narrow signed
    /// integer) and EXPR contains `.len`, OR NAME is subsequently used
    /// as an array subscript `[NAME`.  When the collection has more
    /// items than iN can represent, the index wraps — the loop never
    /// executes or runs in reverse.  Catches oven-sh/bun#31129
    /// (url_path reverse scan) and oven-sh/bun#31339 (SQL result) class.
    index_type_narrowing_wraparound,
    /// `.field = recv.field` inside a struct literal where the field
    /// name suggests a refcounted / heap-owned type (`name`, `str`,
    /// `string`, `ref`, `handle`, `buf`, `data`, `content`) and no
    /// ref-acquire method (`clone()` / `dupeRef()` / `ref()` / etc.)
    /// is called on `recv.field` in the surrounding tokens.  Both the
    /// source and the copy will call the destructor on the same
    /// allocation → double-decrement → SIGFPE or UAF.  Catches
    /// oven-sh/bun#30955 (Blob.name SIGFPE), oven-sh/bun#30991 (WTF
    /// string ref), oven-sh/bun#30882 (specifier dupe_ref) class.
    ref_counted_copy_without_dupe,
    /// `const bytes = buf.slice();` (or `.utf8()`, `.latin1()`,
    /// `.utf16()`, etc.) takes a raw pointer into a JSC-managed
    /// buffer.  A subsequent call that enters the JS engine (e.g.
    /// `vm.call(...)`, `vm.evaluate(...)`) may trigger GC, which can
    /// move or free the backing buffer.  Bytes now dangles.  Fix:
    /// call `.pin(globalObject)` before taking the slice and
    /// `.unpin()` after.  Catches oven-sh/bun#31339 class.
    arraybuffer_slice_without_pin,
    /// `self.remoteSettings orelse self.localSettings` uses the wrong
    /// fallback direction — the left-hand field is likely a peer-
    /// advertised value; when absent (null), the code falls back to
    /// the locally-configured limit, silently relaxing a security
    /// check.  The fallback should use the local limit directly.
    /// Catches oven-sh/bun#31129 class (h2_frame_parser.zig).
    optional_fallback_wrong_side,
    /// Inside a loop, `if (buf[i] == ESCAPE_CHAR) { i += 1; }` is
    /// immediately followed by an unconditional `i += 1;` without a
    /// preceding bounds guard `i + 1 < buf.len`.  If the escape char
    /// is the last byte, the skip pushes `i` to `buf.len`; the
    /// subsequent unconditional `+= 1` or the next iteration reads
    /// past the end.  Fix: add `i + 1 < buf.len and` before the array
    /// access in the if condition.
    /// Catches oven-sh/bun#31435 (fmt.zig JS syntax highlighter).
    escape_skip_without_bounds_recheck,
    /// A fn whose name contains "parse", "skip", "visit", or "scan"
    /// calls itself recursively without a stack-depth guard
    /// (`is_safe_to_recurse()` / `isSafeToRecurse()` /
    /// `isStackOverflow()`).  Deeply nested input (e.g. thousands of
    /// nested type expressions, statement blocks, or AST nodes) will
    /// exhaust the call stack and crash the process.
    /// Fix: add `if (!stack_check.is_safe_to_recurse()) return
    /// error.StackOverflow;` at the entry of the function.
    /// Catches oven-sh/bun#31361 / #31333 class.
    recursive_parse_without_stack_check,
    /// `buf[N..]` where `N` is a non-zero integer literal and no `buf.len`
    /// check appears in the fn body before the slice expression.  When
    /// `buf.len < N`, this is a safety-checked OOB trap (Debug/Safe) or
    /// undefined behaviour (ReleaseFast).  Common in parsers that slice off
    /// fixed-size prefixes ("--- a/", "HTTP/1.1 ", etc.) without validating
    /// that the input is at least N bytes long.  Fix: add
    /// `if (buf.len < N) return error.TruncatedInput;` before the slice.
    /// Catches oven-sh/bun#31227 / #31264 class.
    slice_from_fixed_offset_without_len_check,
    /// `-value << N` where `value` is a signed integer variable and no
    /// `std.math.minInt` guard appears in the fn body.  When
    /// `value == minInt`, negation overflows in two's complement (wraps
    /// back to `minInt`); the subsequent left shift produces wrong output
    /// or undefined behaviour in ReleaseFast.  Fix: use `@bitCast` /
    /// `@as(u32, @intCast(value))` or add an explicit minInt check.
    /// Catches oven-sh/bun#10782 (sourcemap.zig encodeVLQ overflow).
    negate_then_shift_without_minint_check,
    /// `const <X> = try <reader>.readInt(...)` (or readU32 / readU64 /
    /// readByte / etc.) deserializes an integer from untrusted data, then
    /// `<recv>.<pos_field> = <X>` assigns it to a position/cursor/offset
    /// field without a preceding `if (<X> > <recv>.buffer.len) return
    /// error.CorruptData;`.  The unchecked cursor is later used to slice
    /// the buffer, causing an out-of-bounds trap (Debug/Safe) or memory
    /// disclosure (ReleaseFast).  Fix: validate `<X> <= buffer.len`
    /// before writing the cursor.  Catches oven-sh/bun#12105 class
    /// (lockfile.zig Buffers.readArray).
    readint_unchecked_position_assignment,
    /// `list.items[list.items.len] = value;` — writes one slot past the
    /// initialized region without ensuring capacity first.  When
    /// `items.len == capacity` (the ArrayList is exactly full), this
    /// writes into allocator bookkeeping bytes, producing a safety-checked
    /// OOB trap in Debug mode or silent heap corruption in ReleaseFast.
    /// Fix: `try list.ensureUnusedCapacity(1); list.appendAssumeCapacity(value);`.
    /// Catches oven-sh/bun#29982 class (toUTF16Alloc sentinel branch).
    arraylist_sentinel_write_without_capacity,
    /// `@intFromFloat(<expr>)` without a `@min` / `@max` / `std.math.clamp`
    /// guard wrapping the argument.  Timer values, peer-advertised delays, and
    /// GC-scheduler floats can be ±Inf or exceed the target integer's range —
    /// `@intFromFloat` panics in Debug/Safe and produces undefined behaviour
    /// in ReleaseFast for those inputs.
    /// Fix: `@intFromFloat(@min(@max(x, min_f), max_f))` or `std.math.lossyCast`.
    /// Catches oven-sh/bun#28364 + #29328 class.
    intfromfloat_without_clamp,
    /// `data.len < (a + b)` — bounds check where the sum `(a + b)` is
    /// computed in a narrower integer type (e.g. `u32`) and may wrap to a
    /// small value before comparison against the `usize` length.  The guard
    /// evaluates `false` for huge inputs, bypassing it.  Fix: subtract to
    /// keep everything in `usize`: `data.len - a < b`; or explicitly widen:
    /// `@as(usize, a) + @as(usize, b)`.
    /// Catches oven-sh/bun#30157 class (IPC message decoder u32 wraparound).
    int_sum_overflow_in_bounds_cmp,
    /// `.ptr[0..N]` for N ∈ {2, 3, 4} bypasses Zig's slice length check.
    /// If the source slice has fewer than N bytes, this reads past the
    /// end of the allocation — silent OOB read in ReleaseFast, or memory
    /// disclosure / corruption.  Add a `if (slice.len < N) return error.Truncated`
    /// guard before using `.ptr` for a fixed-size window.
    /// Catches oven-sh/bun#29999 class (CodepointIterator.next: `.ptr[0..4]`
    /// without checking `bytes.len >= 4` at end-of-input).
    ptr_slice_without_bounds_check,
    /// `recv.lock()` called a second time on the same receiver without a
    /// preceding `recv.unlock()`.  `std.Thread.Mutex` is non-reentrant:
    /// a second `lock()` on the same thread deadlocks in ReleaseFast
    /// (spins forever) and asserts in Debug.  Unlock before re-acquiring.
    /// Catches oven-sh/bun#28907 class (ThreadPool sync deadlock).
    mutex_double_lock,
};

pub const all_invariants: [74]Invariant = .{
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
    .arraylist_element_ptr,
    .fd_write_after_close,
    .slice_of_arena_into_heap,
    .free_without_null_then_check,
    .tagged_union_retag_with_old_payload_read,
    .union_deinit_without_inert_reset,
    .self_undefined_after_destroy,
    .missing_errdefer_on_out_param,
    .reset_skips_pooled_resource_release,
    .return_borrowed_payload,
    .unreleased_factory_handle,
    .memset_undef_after_len_truncation,
    .publish_then_touch_self,
    .assert_on_untrusted_input,
    .missing_deinit_on_composed_owner,
    .owned_field_no_outer_cleanup,
    .borrowed_slice_into_out_param,
    .defer_and_errdefer_free_overlap,
    .sentinel_strip_free_size_mismatch,
    .move_out_without_restore,
    .deinit_order_violates_construction_dep,
    .borrowed_slice_into_stack_buffer_returned,
    .iterator_invalidation_mutation,
    .thread_spawn_local_pointer,
    .self_pointer_in_returned_value,
    .todo_panic_in_production,
    .getorput_unguarded_value_read,
    .hashmap_iter_mutation,
    .ref_before_ownership_transfer,
    .opt_capture_ptr_after_field_clear,
    .tagged_union_payload_early_exit,
    .union_payload_ptr_after_variant_change,
    .flag_reset_after_callback,
    .slice_loop_reentrant_grow,
    .scope_push_pop_imbalance,
    .exit_callback_cross_thread,
    .index_type_narrowing_wraparound,
    .ref_counted_copy_without_dupe,
    .arraybuffer_slice_without_pin,
    .optional_fallback_wrong_side,
    .escape_skip_without_bounds_recheck,
    .recursive_parse_without_stack_check,
    .slice_from_fixed_offset_without_len_check,
    .negate_then_shift_without_minint_check,
    .readint_unchecked_position_assignment,
    .arraylist_sentinel_write_without_capacity,
    .intfromfloat_without_clamp,
    .int_sum_overflow_in_bounds_cmp,
    .ptr_slice_without_bounds_check,
    .mutex_double_lock,
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
