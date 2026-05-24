# zbc

A Bug Checker for Zig.  Catches use-after-free, double-free,
arena escape, missing errdefer, stack-fallback escape, refcount
leaks, pointer-stability footguns, and 30+ other lifetime /
ownership / cleanup bugs.

## Quick example

```zig
const Owner = struct {
    data: []u8,
    pub fn deinit(self: *Owner, gpa: std.mem.Allocator) void {
        gpa.free(self.data);
    }
};

var owner = Owner{ .data = try gpa.alloc(u8, 16) };
const x = owner.data;       // borrow of owner.data
owner.deinit(gpa);          // gpa.free(self.data) inferred as takes-ownership
_ = x;                      // → heap-use-after-free
```

No annotations, no setup — the body of `deinit` is enough for inference to
recognize that calling `owner.deinit(gpa)` invalidates `owner.data`.

## Usage

```sh
zig build -Doptimize=ReleaseFast   # ~200× faster than Debug on sweeps
zbc path/to/file.zig
zbc path/to/dir              # recursive
zbc --format=compact path     # grep-friendly
zbc --list-rules
zbc --explain <rule-id>
```

**Build mode matters.** Default `zig build` produces Debug, which
is ~200× slower than ReleaseFast on multi-file sweeps (bun's
1290-file corpus: Debug ~6 min wall, ReleaseFast ~1.8 s wall).
Always prefer ReleaseFast (or ReleaseSafe for bounds-checked
runs) on sweeps; Debug is fine only for single-file or
test-driven workflows.

Exit 0 if clean, 1 if problems found.  Default output uses a
caret + secondary span pointing at the free / kill / borrow site.

## Rules

45 rules in two analysis families:

**Flow analysis** — full per-fn control-flow graph + abstract
interpretation:

- `heap-use-after-free`, `heap-double-free`, `arena-use-after-kill`,
  `arena-escape`, `stack-escape`, `use-undefined`,
  `allocator-mismatch`, `interior-pointer-destroy`

**Pattern detectors** — per-fn token-walk over canonical bug shapes
mined from open-source Zig PRs.  Shared infrastructure in `lexer.zig`
/ `scope.zig` / `receiver.zig` / `model.zig` / `local.zig`; see
[ARCHITECTURE.md](ARCHITECTURE.md).

- Heap-leak / aliasing: `heap-leak`, `partial-union-write`,
  `aliased-heap-dupe`, `clobbered-by-struct-reset`,
  `realloc-byte-count`, `asymmetric-field-free`,
  `free-without-null-then-check`,
  `overwrite-without-deinit`
- Error-path cleanup: `missing-errdefer-between-tries`,
  `free-then-try-realloc`, `destroy-after-deinit-in-loop`,
  `dead-errdefer-in-result-fn`, `duplicate-errdefer`,
  `missing-errdefer-on-out-param`, `unreleased-refs-on-error`,
  `unreleased-factory-handle`
- Pointer/slice stability: `hashmap-getptr-rehash`,
  `arraylist-items-slice`, `fd-write-after-close`,
  `stack-fallback-escape`, `slice-of-arena-into-heap`,
  `borrowed-slice-into-out-param`,
  `borrowed-slice-into-stack-buffer-returned`,
  `memset-undef-after-len-truncation`,
  `sentinel-strip-free-size-mismatch`
- Tagged-union semantics:
  `tagged-union-retag-with-old-payload-read`,
  `union-deinit-without-inert-reset`,
  `self-undefined-after-destroy`,
  `return-borrowed-payload`
- Lifecycle / sibling-method consistency:
  `reset-skips-pooled-resource-release`,
  `missing-deinit-on-composed-owner`,
  `owned-field-no-outer-cleanup`,
  `deinit-order-violates-construction-dep`,
  `defer-and-errdefer-free-overlap`,
  `move-out-without-restore`
- Concurrency / hardening: `publish-then-touch-self`,
  `assert-on-untrusted-input`

Run `zbc --list-rules` for the full descriptions, or
`zbc --explain <rule-id>` for the rule's rationale, canonical bug,
fix, and detection notes.

Each rule was extracted from real bug-fix PRs in Bun, TigerBeetle,
Ghostty, Mach, or ziglang/zig's standard library.  The fixture
in `test/fixtures/` documents the PR each rule was mined from.

## Analysis is pure-inference

No annotations are read.  Every signal — heap-vs-arena origin,
ownership transfer, borrow-from-parameter, allocator identity — is
derived from body shape via the flow analyzer and the per-file
FnSummary inference (`fn_summary.zig`).  Cross-module type
questions go through ZLS (`zls_resolver.zig`).

When a finding is wrong, suppress that line with
`// zbc-disable-line:<rule-id>` or
`// zbc-disable-next-line:<rule-id>`.  There is no syntax for
asserting alternative semantics — the tool's belief is what it is.

## Library use

```zig
const zbc = @import("zbc");

const problems = try zbc.analyzeEscape(gpa, io, path, &zbc.DefaultConfig);
defer zbc.freeProblems(gpa, problems);
```

Cross-module type resolution is handled internally via ZLS (declared as
a build-time dependency in `build.zig.zon`).  No setup required.
