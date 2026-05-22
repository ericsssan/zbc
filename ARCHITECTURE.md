# zbc architecture

zbc is a static analyzer for Zig.  Its 46 rules fall into two
families distinguished by the analysis they require:

1. **Flow analysis** — full per-fn control-flow graph and abstract
   interpretation.  Tracks values across branches, loops, defers,
   captures, and out-params.  Used for must-not-escape /
   must-not-double-free / must-not-use-after-free guarantees.
2. **Pattern detectors** — per-fn (or per-file) token / AST walks
   over canonical bug shapes mined from open-source Zig PRs.
   Cheaper than flow analysis; targets recurring "look for this
   exact shape" classes.

Both families produce `Problem` values for the same reporter.

This document focuses on the pattern-detector infrastructure
(`lexer.zig` / `scope.zig` / `receiver.zig` / `model.zig` /
`local.zig` / `testing.zig` / `trace.zig`) — the shared modules
every pattern rule builds on.  See `cfg.zig` / `analyzer.zig` /
`abstract_state.zig` / `transfer.zig` for the flow-analysis side.

## File layout

```
zbc/
├── lib.zig                   — orchestrator; re-exports public API
├── main.zig                  — CLI
├── problem.zig               — Problem / Note / Pos / Severity
├── config.zig                — Config + Invariant enum
│
├── lexer.zig                 — token primitives (matchBrace, FnDeclIter, …)
├── scope.zig                 — scope-aware iterators (BodyWalk, …)
├── receiver.zig              — name classifiers (isAllocatorishName, …)
├── model.zig                 — FileModel: per-file TypeTable + FnTable
├── local.zig                 — LocalBindings: per-fn binding-origin tracker
├── testing.zig               — expectFires / expectNoFire / expectCount
├── trace.zig                 — --trace=<rule-id> decision log
│
├── cfg.zig                   — flow-analysis CFG builder
├── analyzer.zig              — flow-analysis dispatch
├── abstract_state.zig        — flow-analysis abstract domain
├── transfer.zig              — flow-analysis transfer functions
│
└── rules/
    ├── <rule_name>.zig       — pattern-detector implementation
    └── <rule-name>.md        — per-rule documentation
```

Files at root are imported directly by rules:

```zig
const lexer   = @import("../lexer.zig");
const scope   = @import("../scope.zig");
const fmodel  = @import("../model.zig");
const local   = @import("../local.zig");
const testing = @import("../testing.zig");
const trace   = @import("../trace.zig");
```

No umbrella module.  Each module is a clean dependency.

## Shared infrastructure for pattern detectors

### `lexer.zig` — token primitives

Allocation-free helpers that work on a `tags: []const Token.Tag`
slice extracted once via `tree.tokens.items(.tag)`.

Key fns:

- `matchBrace` / `matchParen` / `matchBracket` — given an opener,
  find the matching closer.
- `findStmtSemicolon` — next `;` at paren/brace/bracket depth 0.
- `skipDeferStmt` — given `defer` / `errdefer` keyword, jump past
  the entire deferred statement.
- `skipNestedFn` / `skipNestedFnProtoAndBody` — skip nested fn
  bodies to avoid re-scanning them through their enclosing fn.
- `hasTokenInRange` — true iff any token in `[start, end]` has a
  given tag.
- `returnsType` — true iff a fn returns the literal `type` (a
  type-builder fn; skip to avoid double-scanning its inner body).
- `fnProto` / `bodyOf` — extract proto / body of an `fn_decl`
  across the four AST variants.
- `FnDeclIter` / `iterFnDecls(tree)` — iterate every fn_decl in
  the file, skipping type-builders.

Conventions:

- `last` is the **inclusive** upper bound of the scan window.
- All "find" helpers return `?TokenIndex` so the caller can
  `orelse continue`.
- Token-tag gotcha: `.?` is two tokens (`period` + `question_mark`),
  but `.*` is one token (`period_asterisk`).

### `scope.zig` — scope-aware iteration

Three reusable iterators that encode the three patterns every
precision-tightened rule needs:

- `findIdentUseInEnclosingScope` — bounded by the enclosing `}`;
  allows nested blocks inside the scope; sibling scopes with the
  same name don't match (shadow-aware).
- `findReceiverCallSameDepth(tree, start, last, recv, methodPred)`
  — find a `<recv>.<method>(` call at the SAME block depth as
  `start`.  Skips nested blocks (deeper-scope mutates don't always
  execute) and `defer` / `errdefer` (deferred, not inline).
- `BodyWalk` — cursor over a fn body with `atNestedFn` /
  `skipNestedFn` / `atDeferKeyword` / `skipDeferStmt` helpers.

### `receiver.zig` — name classifiers

Stable name-based filters used across many rules.  Centralizing
keeps "is this an allocator?" / "is this a cleanup method?"
consistent project-wide.

Classifiers:

- `isAllocatorishName` (gpa, alloc, allocator, *_alloc, *Allocator, …)
- `isSelfReceiverName` (self, this)
- `isCanonicalOutName` (result, out, r)
- `isCleanupMethodName` (deinit, free, destroy, close, …)
- `isAcquireMethodName` (reference, retain, addRef, …; ref excluded)
- `isReleaseMethodName` (release, deref, unref, …)
- `isAllocMethodName` (alloc, allocSentinel, dupe, dupeZ, create, …)
- `isDestructorFnName` (deinit*, destroy*, take*, consume*, …)
- `isIdempotentResetFnName` (reset, clear, end, …)

### `model.zig` — FileModel (TypeTable + FnTable)

Per-file semantic model, built ONCE per `Ast`.  Replaces ad-hoc
per-rule type / fn table-building.

```zig
var model = try fmodel.build(gpa, &tree);
defer model.deinit();

// Types
const ti = model.findType("Outer") orelse return;
if (ti.hasMethod("deinit")) ...
if (ti.hasCleanupMethod()) ...      // any of deinit/close/destroy/free/...
for (ti.fields) |f| ...              // f.name, f.type_first..type_last, f.has_default
for (ti.methods) |m| ...             // m.name, m.body_first, m.body_last, m.receiver

// Top-level fns (NOT methods — those live in TypeInfo.methods)
for (model.fns) |f| ...               // f.is_pub, f.returns_error_union
```

Scope (v1):

- Top-level `const Name = struct/union/enum/opaque { ... }` decls.
- Methods + best-effort struct fields within those decls.
- Top-level fn_decl nodes (NOT methods).

Out of scope (v1; add when a rule needs them):

- Nested types (struct inside struct).
- Anonymous types (`return struct { ... }`).
- extern fns / extern structs.

### `local.zig` — LocalBindings (per-fn binding origins)

Per-fn-body model.  For every `const NAME = <expr>` / `var NAME =
<expr>` and every fn parameter, classify the **origin**:

```zig
var bindings = try local.build(gpa, &tree, proto, body);
defer bindings.deinit();

const x = bindings.find("x") orelse return;
switch (x.origin) {
    .param        => ...,
    .literal      => ...,
    .call         => |c| ...,           // free fn call: foo()
    .method_call  => |c| ...,           // method: recv.method()
    .try_call     => |c| ...,           // try foo()
    .alias        => |other_name| ...,  // const X = Y
    .field_access => |fa| ...,          // const X = self.field
    .addr_of      => |aliased| ...,     // const X = &Y
    .index_op     => ...,               // const X = arr[i]
    else => {},
}

// Unified call accessor — strips the try / non-try distinction.
if (x.asCall()) |c| { ... c.receiver, c.method, c.paren_token ... }
```

Replaces hand-rolled one-hop aliasing chains that several rules
currently do for the few questions they need.

### `testing.zig` — rule-test API

One-line test assertions:

```zig
const testing = @import("../testing.zig");
const check = @import("./my_rule.zig").check;
const R = "my-rule-id";

test "fires on the bug" {
    try testing.expectFires(check, R, src);   // exactly 1 problem with id R
}

test "doesn't fire on correct usage" {
    try testing.expectNoFire(check, src);     // zero problems
}

test "n sites" {
    try testing.expectCount(check, R, 3, src);
}
```

On failure each helper dumps observed problems so the first
failing test gives full context — no need for printf-recompile.

Lower-level `runRule(gpa, check, src)` + `freeProblems(gpa, &p)`
are available for tests that need raw problem inspection.

### `trace.zig` — `--trace=<rule-id>` decision log

Rules emit decision events:

```zig
const trace = @import("../trace.zig");
const R = "my-rule-id";

trace.note(R, tree, t, "matched binding via opener");
trace.skip(R, tree, t, "close is inside defer");
trace.match(R, tree, use_tok, "use after close");
trace.enter(R, tree, t, "entering body");
```

By default the calls are no-ops (one compare-and-branch).  The
user runs:

```bash
zbc --trace=fd-write-after-close path/         # one rule
zbc --trace='*' path/                           # all rules
```

… and stderr fills with `[trace:<rule-id>] <kind> @ <line:col>: <msg>`.

## Adding a new rule

1. **Pick a name** in `kebab-case` (the rule ID) and `snake_case`
   (the file name).  E.g., `fd-write-after-close` →
   `rules/fd_write_after_close.zig`.

2. **Add the invariant** to `config.zig`:
   ```zig
   pub const Invariant = enum {
       ...
       my_rule_name,
   };
   pub const all_invariants: [N]Invariant = .{
       ...
       .my_rule_name,
   };
   ```
   Bump the array length.

3. **Write the rule** in `rules/<rule_name>.zig`:
   ```zig
   const std = @import("std");
   const Ast = std.zig.Ast;

   const lexer = @import("../lexer.zig");           // if you need token walks
   const scope = @import("../scope.zig");           // if you need scope iteration
   const fmodel = @import("../model.zig");          // if you need type/fn info
   const local = @import("../local.zig");           // if you need binding origins
   const problem = @import("../problem.zig");
   const testing = @import("../testing.zig");
   const trace = @import("../trace.zig");
   const config_mod = @import("../config.zig");

   const R = "my-rule-id";

   pub fn check(
       gpa: std.mem.Allocator,
       tree: *const Ast,
       config: *const config_mod.Config,
       problems: *std.ArrayListUnmanaged(problem.Problem),
   ) !void {
       if (!config_mod.isEnabled(config, .my_rule_name)) return;
       // ... detection logic ...
   }
   ```

4. **Add inline tests** at the bottom of the rule file using
   `testing.expectFires` / `testing.expectNoFire`.  Cover the
   canonical bug + the most likely false-positive shape +
   2-3 edge cases.

5. **Wire it into the analyzer** in `lib.zig`:
   - `const my_rule_mod = @import("rules/my_rule_name.zig");`
   - In `analyzeEscape`: `try my_rule_mod.check(gpa, &tree, config, &problems);`
   - In the test block: `_ = my_rule_mod;`

6. **Add to the rule catalog** in `rule_catalog.zig`:
   ```zig
   .{
       .id = "my-rule-id",
       .title = "<one-line summary>",
       .body = @embedFile("rules/my-rule-id.md"),
   },
   ```

7. **Write `rules/my-rule-id.md`** with the bug class, bad/good
   examples, and detection notes.  This is what `zbc --explain
   my-rule-id` prints.

8. **Sprinkle trace calls** at decision points — `trace.skip`
   for early exits, `trace.match` for the fire point.  Future
   you debugging will thank present you.

9. **Sweep the corpora** to validate behavior:
   ```bash
   zig build -Doptimize=ReleaseFast
   for repo in bun mach tigerbeetle ghostty Ez; do
       count=$(./zig-out/bin/zbc /Users/ericsan/Development/OpenSource/$repo \
           2>&1 | grep -c "my-rule-id")
       echo "$repo: $count"
   done
   ```
   Spot-check a few hits to confirm they're real (or at least
   "useful noise" — every static analyzer reports some).

## Performance notes

- `zig build -Doptimize=ReleaseFast` is essential for corpus
  sweeps.  Debug-mode runs are ~10× slower.
- The `Io.Group.concurrent` thread pool is lazy in Debug — it
  effectively runs single-threaded.  Always sweep with
  ReleaseFast.
- Each rule's `check` fn runs on the parsed Ast.  Parsing the
  Ast is the dominant cost; rule checks are cheap.  Building
  FileModel / LocalBindings is amortized — they're built ONCE
  per file regardless of how many rules use them.
