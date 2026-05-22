# DSL gaps — what real rule migrations exposed

Notes from migrating 10 production rules onto the `local.zig` /
`query.zig` / `model_query.zig` DSLs.  Each gap is something a
real rule HIT during migration that the DSL didn't cleanly express.

## Hit during migration

### G1. ~~`local.zig` only tracks single-identifier bindings~~ — FIXED

**Resolution:** added `query.capture_until` + `query.ref_range`
atoms (commit 597df5e).  Took the "more general" fix path from
the original analysis: a token-range capture/ref pair that any
rule can use, not just `local.zig`-style binding rules.

  .capture_until = .{ .slot, .stops = &.{TokenTag, ...} }
  .ref_range = slot

`free_then_try_realloc` migrated as the witness: 264 → 208 LOC
(-56, -21%), 100+ lines of token comparison collapsed to 2 atom
patterns + a 10-line loop.

`aliased_heap_dupe` Phase 3 (the other rule named in this gap)
doesn't actually need this — its `<dst>.<field>_allocated`
pattern is a runtime-constructed identifier, handled by the
existing `.text = runtime_string` atom shape.

### G2. `query.zig` has no disjunction

Several rules need "match pattern A OR pattern B" semantics:

- `self_undefined_after_destroy`: `<X>.* = …` OR `<X>.<field> = …`
  — called `findInSameScope` twice and took the earlier match.
- `borrowed_slice_into_out_param`: `<out>.* = …` AND `<out>.<field> = …`
  — same pattern.
- `unreleased_factory_handle`: cleanup is `defer X.release()` OR
  `defer X.deinit()` OR ... — currently uses `.pred = isReleaseMethod`
  but the broader disjunction at atom level would be cleaner.

**Workaround:** call the finder twice and take min, OR pred-filter
inside a single atom.

**Fix:** add `.{ .any_of = &[_][]const Atom{...} }` atom variant.

### G3. ~~method-call chains lose the outermost call~~ — FIXED

**Resolution:** added `outermost_method` / `outermost_method_token`
/ `outermost_paren_token` to `CallInfo` (commit dfc5b58), plus
convenience methods `lastMethod() / lastParen() / isChained()`.

Multi-segment receiver paths (`std.heap.page_allocator.alloc(...)`)
also now classify properly — they're a single call with deep
receiver (chain walk collects all chain identifiers; the LAST
before the `(` is the method).

Witness migration: `slice-of-arena-into-heap`'s Shape A
(`handle.alloc`) and Shape B (`arena.allocator().alloc`)
collapsed into one classification branch via `lastMethod() +
isChained()`.  The `inline_arena_alloc` fallback pattern is
deleted.

Future beneficiaries: `missing-errdefer-between-tries` has a
custom `parseTypeMethodAfter` that could be replaced with
`b.asCall() + lastMethod`.

### G4. `local.zig` doesn't track loop captures

`for (items) |x|` introduces `x` as a local, but `local.build`
only walks `const`/`var` declarations.  `destroy_after_deinit_in_loop`
needs loop captures specifically — couldn't migrate without
extending `local.zig`.

**Fix:** parse `for (...) |x|` and `for (...) |x, i|` capture
clauses into bindings with origin `.loop_capture`.  Capture
clauses on `if`/`while` should also be handled.

### G5. ~~`model_query.zig` only handles top-level types~~ — FIXED

**Resolution:** added recursive `collectTypesInRange` to
`model.build`; `TypeInfo` gained a `parent: ?u32` field pointing
at the index of the enclosing type.  Nested types land in the same
flat `types` list, so `mq.findTypes(...)` picks them up
automatically — no rule changes required.

`FileModel.findType` is still first-match-wins; name collisions
across nest levels accept the conservative behavior since the
existing 2 consumers iterate the full list anyway.

Bug yield: bun corpus +16 new TPs (8 missing-deinit-on-composed-
owner, 8 owned-field-no-outer-cleanup) for previously-invisible
nested-type cleanup methods.  E.g., `ResultListEntry.Value` (a
union inside `ResultListEntry` inside an outer struct) exposes a
real `deinit` whose absence in the outer's destructor was a real
leak.  Tigerbeetle: unchanged.

### G6. ~~No "capture WITH predicate" atom~~ — FIXED

**Resolution:** added `pred_at` and `text_at` Atom variants to
query.zig.  Both match an identifier AND fill a capture slot in a
single atom, eliminating the `m.start + N` offset arithmetic that
was the fragile workaround.

Witness migration: `missing_errdefer_on_out_param` now uses
`.{ .pred_at = .{ .slot = 1, .pred = isCanonicalOutName } }` and
`.{ .pred_at = .{ .slot = 2, .pred = isAcquireMethodName } }` to
capture `<out>` and `<method>` tokens by slot.  Report site
references `m.captures[1].?` / `m.captures[2].?` — pattern atoms
can be inserted/removed without silently breaking the offsets.

Also adopted in three patterns from earlier session: sentinel_strip
(slot for `free`), publish_call (slots for method + arg),
addref_call_pattern (slot for method).

### G7. ~~method-call origins don't preserve `try` distinction~~ — FIXED

**Resolution:** added `Binding.wasTryWrapped(tags) bool` helper.
Returns true for `.try_call` / `.try_method_call` origins AND for
non-call shapes whose RHS starts with `try` (e.g.
`const X = try expr` where `expr` isn't a recognized call).

`missing_errdefer_between_tries` migrated as the witness: dropped
the two-line `if (b.rhs_first > b.rhs_last) continue;` +
`if (tags[b.rhs_first] != .keyword_try) continue;` to a single
`if (!b.wasTryWrapped(tags)) continue;` call.

### G8. ~~The 16+ same-named local classifiers~~ — FIXED

**Resolution:** renamed the two predicate functions that
intentionally diverged from receiver.zig's canonical vocabulary:

- `unreleased_refs_on_error.isAddrefMethodName` →
  `isStrictAddrefMethodName` (excludes `acquire` to dodge
  `mutex.acquire()` collisions).
- `defer_and_errdefer_free_overlap.isFreeOrDestroyName` →
  `isAllocPairCleanupName` (narrow subset of
  `receiver.isCleanupMethodName`, only the alloc-pair cleanup
  names that defer-free-overlap cares about).

Other rule-local classifiers (already named after their semantic
intent — `isDestroyOrFree`, `isOpenerMethod`, etc.) don't collide
with the receiver.zig vocabulary and need no rename.

## Not hit (yet) — theoretical

### T1. No cross-fn analysis

All rules are intra-fn.  Bugs that span fn calls (e.g., a fn
takes ownership of an arg, the caller still uses it) are out of
scope.  Would need a call-graph + summary infrastructure.

### T2. No type-system integration

Rules approximate types via heuristics (`isAllocatorishName`,
`isCanonicalOutName`, `isCleanupMethodName`).  The actual Zig
type system (with comptime-resolved types) isn't accessible at
syntactic-rule level.  Inherent to "purely syntactic" rules.

### T3. Position info in trace.zig is rudimentary

Trace events show `line:col` but not the source file path.  In
corpus sweeps, every trace event looks alike.  Easy fix
(pass tree's filename into trace context).

## Status

| Gap | Status | Notes |
|---|---|---|
| G1 (field-paths) | **fixed** | query.capture_until + ref_range; free_then_try_realloc migrated -56 LOC |
| G2 (disjunction) | **fixed** | query.any_of; self_undefined + borrowed_slice cleaned up |
| G3 (chained calls) | **fixed** | local.CallInfo gains outermost_*; slice_of_arena -23 LOC |
| G4 (loop captures) | **fixed** | local.loop_capture; destroy_after_deinit_in_loop migrated |
| G5 (nested types) | **fixed** | model.collectTypesInRange recurses; +16 TPs on bun |
| G6 (capture+pred) | **fixed** | query.pred_at + text_at; missing_errdefer_on_out_param cleaned |
| G7 (try distinction) | **fixed** | Binding.wasTryWrapped helper; missing_errdefer_between_tries cleaned |
| G8 (classifier naming) | **fixed** | renamed isAddrefMethodName / isFreeOrDestroyName |

All 8 hit-during-migration gaps closed.  Remaining items in this
doc (T1-T3) are theoretical / out-of-scope for the pattern detector
infrastructure.
