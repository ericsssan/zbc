# DSL gaps — what real rule migrations exposed

Notes from migrating 10 production rules onto the `local.zig` /
`query.zig` / `model_query.zig` DSLs.  Each gap is something a
real rule HIT during migration that the DSL didn't cleanly express.

## Hit during migration

### G1. `local.zig` only tracks single-identifier bindings

`local.Binding` records `name` (single identifier).  Many rules
need to track **field-path expressions** as the "thing being
managed":

- `free_then_try_realloc`: `<x>.free(s.columns); s.columns = try ...;` —
  the freed/reassigned thing is `s.columns`, a 3-token field path.
- `aliased_heap_dupe` Phase 3: `<dst>.<field>_allocated = false` —
  remediation pattern keyed on the dst+field pair, not a binding.

**Why it's a gap:** rules end up with custom token-walks for
multi-token "path" patterns the DSL can't capture.

**Workaround in use today:** rules with field-paths skip
`local.zig` entirely (free_then_try_realloc was the cleanest
example) OR fall back to bespoke token scans.

**Fix shapes:**
- Extend `local.zig` with a `FieldPathBinding` variant tracking
  `<recv>.<field>...` sequences alongside identifier bindings.
- OR add `query.zig` atoms for "capture token range, ref it
  later" (`.capture_range = .{ .slot, .until = .r_paren }` + `.ref_range = N`).
- The second is more general; the first is cheaper.

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

### G3. method-call chains lose the outermost call

`local.classifyOrigin` captures only the FIRST two identifiers
of a method-call chain:

- `arena.allocator()` → `method_call(receiver=arena, method=allocator)` ✓
- `arena.allocator().alloc(...)` → ALSO `method_call(receiver=arena,
  method=allocator)` ✗ — loses the `.alloc(...)` outer call

**Why it matters:** the chained form is common in idiomatic Zig
(`std.heap.page_allocator.alloc(...)`, `arena.allocator().dupe(...)`).
Rules like `slice-of-arena-into-heap` need the OUTER method
(`alloc`/`dupe`) to classify; they fall back to a token pattern
(`inline_arena_alloc`) for the chained form.

**Fix shapes:**
- Add `Origin.chained_method_call` capturing the OUTERMOST call's
  receiver+method, with `inner` pointing at the first-call info.
- OR replace `CallInfo.method` with a `methods: []const []const u8`
  slice covering the full chain.

### G4. `local.zig` doesn't track loop captures

`for (items) |x|` introduces `x` as a local, but `local.build`
only walks `const`/`var` declarations.  `destroy_after_deinit_in_loop`
needs loop captures specifically — couldn't migrate without
extending `local.zig`.

**Fix:** parse `for (...) |x|` and `for (...) |x, i|` capture
clauses into bindings with origin `.loop_capture`.  Capture
clauses on `if`/`while` should also be handled.

### G5. `model_query.zig` only handles top-level types

`model.build` doesn't recurse into nested types (`const Inner =
struct { const Nested = struct { ... }; };`).  Rules wanting
`hasMethod` on nested types don't see them.

**Why it matters today:** owned-field-no-outer-cleanup misses
nested struct fields with cleanup methods.  Bug yield is small
(nested types with cleanup are uncommon), but the abstraction
boundary is leaky.

**Fix:** depth-first walk in `model.build`; `TypeInfo` gains a
`parent: ?u32` field (index into types).  `FileModel.findType`
becomes scoped or fully-qualified.

### G6. No "capture WITH predicate" atom

Common pattern: "match an identifier that passes a predicate, AND
capture its position for later reference."

- `missing_errdefer_on_out_param`: wanted "capture `<out>` where
  `<out>` is in canonical-out names."  Worked around with
  `.{ .pred = isCanonicalOutName }` + post-hoc `tree.tokenSlice(m.start + 1)`
  to retrieve the captured text (fragile — depends on atom-offset
  arithmetic).

**Fix:** add `.{ .capture_pred = .{ .slot, .pred } }` atom that
both filters AND captures.

### G7. method-call origins don't preserve `try` distinction

`Binding.asCall()` returns the unified CallInfo regardless of
whether the binding was `try`-wrapped.  Most rules want this
unification (don't care about `try`), but a few need to
distinguish — currently they check `tags[b.rhs_first] ==
.keyword_try` separately.

**Mild gap.**  Could add `Binding.wasTryWrapped(tags) bool` helper.

### G8. The 16+ same-named local classifiers

`isCleanupMethodName` exists in 3 rule files with DIFFERENT sets
of names.  Not duplication (different semantics), but the shared
name with `receiver.isCleanupMethodName` invites confusion.

**Not a DSL gap so much as a naming-convention gap.**  Each rule
needs a SPECIFIC name-set; receiver.zig's canonical version is
just one of many.

**Fix:** rename rule-local classifiers to be specific
(`isStrictCleanupName`, `isResetFamilyName`, etc.) so they
don't collide with the receiver.zig vocabulary.

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

## Decision: which gap to fix next

Ranked by frequency-hit during migrations:

| Gap | Migrations hit | Workaround cost | Fix size |
|---|---|---|---|
| G1 (field-paths) | 2 rules | high (rule skipped) | M |
| G2 (disjunction) | 3 rules | low (call twice) | S |
| G3 (chained calls) | 1 rule | medium (fallback pattern) | M |
| G4 (loop captures) | 1 rule | high (rule skipped) | S |
| G5 (nested types) | 1 rule (latent FN) | low (not surfaced) | M |
| G6 (capture+pred) | 1 rule | low (offset arithmetic) | S |

**Highest ROI**: G4 (loop captures) — small fix, unlocks
`destroy_after_deinit_in_loop` migration.  G2 (disjunction) —
small fix, eliminates ~3 lines of workaround across 3 rules.

**Highest impact**: G1 (field-paths) — extends local.zig's
reach to a whole class of rules currently using bespoke token
walks (free_then_try_realloc, aliased_heap_dupe's Phase 3,
possibly future rules around field mutation).
