//! Rule documentation catalog for `--list-rules` / `--explain`.
//!
//! This file holds *docs only* — id, one-line title, and the markdown
//! body from `rules/<dir>/<id>.md`.  Dispatch is not here: pattern
//! detectors live in `detectors.zig`, and the CFG/worklist invariants
//! are declared in `flow/invariants.zig`.  The catalog spans both
//! classes because the CLI documents both, and `invariants.zig` checks
//! that every invariant is documented.

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
        .id = "recursive-parse-without-stack-check",
        .title = "recursive parse/skip/visit/scan fn calls itself without `is_safe_to_recurse()` guard — deep input overflows the call stack",
        .body = @embedFile("rules/misc/recursive-parse-without-stack-check.md"),
    },
    .{
        .id = "slice-from-fixed-offset-without-len-check",
        .title = "`buf[N..]` from a non-zero literal offset without a prior `buf.len >= N` check — OOB trap (Debug/Safe) or UB (ReleaseFast)",
        .body = @embedFile("rules/misc/slice-from-fixed-offset-without-len-check.md"),
    },
    .{
        .id = "divmod-by-len-without-nonempty-guard",
        .title = "`x / c.len` or `x % c.len` where `c` may be empty — integer division/modulo by zero (panics in Debug/Safe, UB in ReleaseFast)",
        .body = @embedFile("rules/misc/divmod-by-len-without-nonempty-guard.md"),
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
    .{
        .id = "lock-held-across-early-exit",
        .title = "`recv.lock()` leaked on an early-exit path — a `return`/`try` before the matching `recv.unlock()` exits with the lock held; use `defer recv.unlock()`",
        .body = @embedFile("rules/misc/lock-held-across-early-exit.md"),
    },
    .{
        .id = "ptrfromint-zero",
        .title = "`@ptrFromInt(0)` — null pointer to non-nullable type is UB (trap in Debug/Safe, silent corruption in ReleaseFast)",
        .body = @embedFile("rules/misc/ptrfromint-zero.md"),
    },
    .{
        .id = "resize-result-discarded",
        .title = "`_ = allocator.resize(…)` discards in-place-growth bool — slice may still be old length; OOB writes follow",
        .body = @embedFile("rules/heap/resize-result-discarded.md"),
    },
    .{
        .id = "errdefer-alive-after-ownership-transfer",
        .title = "`errdefer X.deinit()` armed after ownership-taking constructor takes `X` — later `try` double-frees `X`",
        .body = @embedFile("rules/errdefer/errdefer-alive-after-ownership-transfer.md"),
    },
    .{
        .id = "f32-narrowing-int-to-float",
        .title = "`@as(f32, @floatFromInt(…))` narrows integer to f32 — values above 2²⁴ silently round, defeating bounds checks",
        .body = @embedFile("rules/misc/f32-narrowing-int-to-float.md"),
    },
    .{
        .id = "array-maxint-off-by-one",
        .title = "`[std.math.maxInt(T)]` array has one slot too few — index `maxInt(T)` is always out of bounds",
        .body = @embedFile("rules/misc/array-maxint-off-by-one.md"),
    },
    .{
        .id = "intcast-clamp-uses-max",
        .title = "`@intCast(@max(…, maxInt(T)))` uses `@max` instead of `@min` — overflows the intended upper bound",
        .body = @embedFile("rules/misc/intcast-clamp-uses-max.md"),
    },
    .{
        .id = "forced-unwrap-iterator-next",
        .title = "`.next().?` force-unwraps iterator result — panics when iterator is exhausted; use `orelse` instead",
        .body = @embedFile("rules/misc/forced-unwrap-iterator-next.md"),
    },
    .{
        .id = "impossible-range-and",
        .title = "`x < A and x > B` dead range check — uses `and` instead of `or`; guard body is permanently unreachable",
        .body = @embedFile("rules/misc/impossible-range-and.md"),
    },
    .{
        .id = "intcast-signed-timestamp",
        .title = "`@intCast(std.time.<fn>())` casts signed i64 timestamp without guard — negative values panic or wrap",
        .body = @embedFile("rules/misc/intcast-signed-timestamp.md"),
    },
    .{
        .id = "truncate-subtraction-without-guard",
        .title = "`@truncate(a - b)` without `a >= b` guard — unsigned underflow wraps before truncation, yielding garbage",
        .body = @embedFile("rules/misc/truncate-subtraction-without-guard.md"),
    },
    .{
        .id = "initcapacity-plain-add-overflow",
        .title = "`initCapacity(alloc, size + N)` plain add overflows when `size` near `maxInt(usize)` — under-allocates, heap corruption follows",
        .body = @embedFile("rules/misc/initcapacity-plain-add-overflow.md"),
    },
    .{
        .id = "index-minus-one-without-zero-guard",
        .title = "`buf[idx - 1]` without `idx > 0` guard — unsigned underflow wraps to `maxInt(usize)` (OOB panic or arbitrary memory read)",
        .body = @embedFile("rules/misc/index-minus-one-without-zero-guard.md"),
    },
    .{
        .id = "else-literal-absorbs-addend",
        .title = "`else 0 + addend` — Zig's `if` has lower precedence than `+`, absorbing the addend into the else-branch and silently dropping it when the condition is true",
        .body = @embedFile("rules/misc/else-literal-absorbs-addend.md"),
    },
    .{
        .id = "catch-error-panic",
        .title = "`catch |err| @panic(...)` — catching an error and panicking turns a recoverable error into a process crash; use `try` to propagate or `catch unreachable` if impossible",
        .body = @embedFile("rules/misc/catch-error-panic.md"),
    },
    .{
        .id = "toutf8-inline-slice-borrow",
        .title = "`.toUTF8(alloc).slice()` inline chain — the temporary `LazyUTF8` is freed at statement end, leaving the returned slice dangling",
        .body = @embedFile("rules/misc/toutf8-inline-slice-borrow.md"),
    },
    .{
        .id = "uv-return-value-intcast-truncation",
        .title = "`@intCast(rc.int())` on a libuv return code — `.int()` returns 32-bit `c_int` but the actual result is 64-bit `ssize_t`; panics for I/O transfers > 2 GB",
        .body = @embedFile("rules/misc/uv-return-value-intcast-truncation.md"),
    },
    .{
        .id = "tryget-orelse-unreachable",
        .title = "`tryGet() orelse unreachable` — `tryGet()` returns null for finalized JSRef objects; `unreachable` becomes SIGILL after finalization",
        .body = @embedFile("rules/misc/tryget-orelse-unreachable.md"),
    },
    .{
        .id = "aligncast-on-byte-slice",
        .title = "`@alignCast(expr.ptr)` — alignment assertion on a raw byte-slice pointer panics non-deterministically for unaligned network/file data",
        .body = @embedFile("rules/misc/aligncast-on-byte-slice.md"),
    },
    .{
        .id = "truncate-len-to-narrow-int",
        .title = "`@truncate(X.len)` — silently discards high bits of a `usize` length; user-controlled data ≥ 2^N bytes wraps to a garbage size",
        .body = @embedFile("rules/misc/truncate-len-to-narrow-int.md"),
    },
    .{
        .id = "field-self-assign-with-cast",
        .title = "`self.field = @as(T, @intCast(self.field))` — self-assign through a cast is a no-op; almost always a copy-paste error where a freshly-computed variable was intended",
        .body = @embedFile("rules/misc/field-self-assign-with-cast.md"),
    },
    .{
        .id = "maybe-assert-panics",
        .title = "`someCall(...).assert()` — chaining `.assert()` on a fallible call converts every OS error into a process crash; check and propagate instead",
        .body = @embedFile("rules/misc/maybe-assert-panics.md"),
    },
    .{
        .id = "return-arraylist-items",
        .title = "`return list.items` — returns the `.items` slice without transferring the backing allocation; caller cannot free it; use `toOwnedSlice()` instead",
        .body = @embedFile("rules/misc/return-arraylist-items.md"),
    },
    .{
        .id = "lessthan-uses-leq",
        .title = "`<=` inside a `lessThan` comparator violates strict weak ordering — `lessThan(a, a)` returns `true`; `std.sort` may loop or produce incorrect results",
        .body = @embedFile("rules/misc/lessthan-uses-leq.md"),
    },
    .{
        .id = "duplicate-defer-free",
        .title = "`defer alloc.free(X)` appears twice in the same fn body — both fire at exit (LIFO), freeing `X` twice; remove the duplicate",
        .body = @embedFile("rules/misc/duplicate-defer-free.md"),
    },
    .{
        .id = "hashmap-getentry-forced-unwrap",
        .title = "`.getEntry(key).?` — `HashMap.getEntry` returns `?Entry`; forced `.?` panics when key is absent; use `if`/`orelse` guard instead",
        .body = @embedFile("rules/collection/hashmap-getentry-forced-unwrap.md"),
    },
    .{
        .id = "double-optional-ptr",
        .title = "`?*?T` — doubly-optional pointer; almost always a copy-paste error; for nullable out-params use `?*T`, for non-null pointer to optional use `*?T`",
        .body = @embedFile("rules/misc/double-optional-ptr.md"),
    },
    .{
        .id = "aligncast-on-optional-unwrap",
        .title = "`@alignCast(x.?)` — forced `.?` panics on null; alignment assertion panics on misalignment; two panic sources in one expression",
        .body = @embedFile("rules/misc/aligncast-on-optional-unwrap.md"),
    },
    .{
        .id = "adjacent-decl-same-source-field",
        .title = "two adjacent `const` bindings read the same struct field — the second likely meant a different field",
        .body = @embedFile("rules/misc/adjacent-decl-same-source-field.md"),
    },
    .{
        .id = "arena-allocator-free-noop",
        .title = "`.allocator().free(x)` on an arena allocator is a no-op — memory is released only by `deinit`",
        .body = @embedFile("rules/misc/arena-allocator-free-noop.md"),
    },
    .{
        .id = "arraylist-element-ptr",
        .title = "`&list.items[i]` borrowed across a call that may grow the list",
        .body = @embedFile("rules/collection/arraylist-element-ptr.md"),
    },
    .{
        .id = "clamp-wrong-direction",
        .title = "`@max(x, maxInt(T))` / `@min(x, minInt(T))` clamp in the wrong direction",
        .body = @embedFile("rules/misc/clamp-wrong-direction.md"),
    },
    .{
        .id = "cmpxchgweak-orelse-break",
        .title = "`cmpxchgWeak(...) orelse break` exits on success — `null` means the exchange happened",
        .body = @embedFile("rules/misc/cmpxchgweak-orelse-break.md"),
    },
    .{
        .id = "intcast-of-negated-signed",
        .title = "`@intCast(-x)` overflows when `x` holds `minInt(T)`",
        .body = @embedFile("rules/misc/intcast-of-negated-signed.md"),
    },
    .{
        .id = "memcpy-overlapping-slices",
        .title = "`@memcpy` with both slices derived from the same base — aliased arguments",
        .body = @embedFile("rules/misc/memcpy-overlapping-slices.md"),
    },
    .{
        .id = "midpoint-addition-overflow",
        .title = "`(a + b) / 2` overflows before the division for large bounds",
        .body = @embedFile("rules/misc/midpoint-addition-overflow.md"),
    },
    .{
        .id = "multiarray-items-deref-assign",
        .title = "`items(.field)[i].* = v` dereferences a field value as a pointer",
        .body = @embedFile("rules/collection/multiarray-items-deref-assign.md"),
    },
    .{
        .id = "slice-write-at-len",
        .title = "`buf[buf.len] = v` writes one past the end of the slice",
        .body = @embedFile("rules/misc/slice-write-at-len.md"),
    },
    .{
        .id = "startswith-strip-off-by-one",
        .title = "prefix stripped with `slice[len - 1..]` leaves one character behind",
        .body = @embedFile("rules/misc/startswith-strip-off-by-one.md"),
    },
    .{
        .id = "struct-literal-multiple-try",
        .title = "multiple `try` in one struct literal — the first allocation leaks if a later one fails",
        .body = @embedFile("rules/misc/struct-literal-multiple-try.md"),
    },
    .{
        .id = "writeint-truncated-value",
        .title = "`writeInt(T, @as(T, @truncate(x)))` silently drops high bits",
        .body = @embedFile("rules/misc/writeint-truncated-value.md"),
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
