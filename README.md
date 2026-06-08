# zbc

A bug checker for Zig — 45 rules covering lifetime, ownership, and cleanup
bugs with no annotations required.

## Example

```zig
const Owner = struct {
    data: []u8,
    pub fn deinit(self: *Owner, gpa: std.mem.Allocator) void {
        gpa.free(self.data);
    }
};

var owner = Owner{ .data = try gpa.alloc(u8, 16) };
const x = owner.data;    // borrows owner.data
owner.deinit(gpa);        // inferred: takes ownership of self.data
_ = x;                    // → heap-use-after-free
```

The body of `deinit` is enough for zbc to infer that calling
`owner.deinit(gpa)` invalidates `owner.data`.

## Build integration

**`build.zig.zon`**

```zig
.dependencies = .{
    .zbc = .{
        .url = "https://github.com/ericsssan/zbc/archive/refs/tags/v0.1.0.tar.gz",
        .hash = "<hash>",  // run: zig fetch --save <url>
    },
},
```

**`build.zig`**

```zig
const zbc_dep = b.dependency("zbc", .{
    .target = target,
    .optimize = .ReleaseFast,
});

const zbc_run = b.addRunArtifact(zbc_dep.artifact("zbc"));
zbc_run.addArg("src/");

b.default_step.dependOn(&zbc_run.step);
```

## CLI

```sh
zig build -Doptimize=ReleaseFast
```

```sh
zbc src/
zbc path/to/file.zig
zbc --format=compact src/
zbc --list-rules
zbc --explain <rule-id>
```

Exit 0 if clean, 1 if problems found.

## Rules

45 rules in two families:

**Flow analysis** — full per-fn CFG + abstract interpretation, tracking
values across branches, loops, defers, captures, and out-params:

`heap-use-after-free`, `heap-double-free`, `arena-use-after-kill`,
`arena-escape`, `stack-escape`, `use-undefined`, `allocator-mismatch`,
`interior-pointer-destroy`

**Pattern detectors** — per-fn token/AST walks over canonical bug shapes
mined from open-source Zig PRs:

- Heap leak / aliasing: `heap-leak`, `partial-union-write`,
  `aliased-heap-dupe`, `clobbered-by-struct-reset`, `realloc-byte-count`,
  `asymmetric-field-free`, `free-without-null-then-check`,
  `overwrite-without-deinit`
- Error-path cleanup: `missing-errdefer-between-tries`,
  `free-then-try-realloc`, `destroy-after-deinit-in-loop`,
  `dead-errdefer-in-result-fn`, `duplicate-errdefer`,
  `missing-errdefer-on-out-param`, `unreleased-refs-on-error`,
  `unreleased-factory-handle`
- Pointer / slice stability: `hashmap-getptr-rehash`,
  `arraylist-items-slice`, `fd-write-after-close`,
  `stack-fallback-escape`, `slice-of-arena-into-heap`,
  `borrowed-slice-into-out-param`,
  `borrowed-slice-into-stack-buffer-returned`,
  `memset-undef-after-len-truncation`,
  `sentinel-strip-free-size-mismatch`
- Tagged-union semantics: `tagged-union-retag-with-old-payload-read`,
  `union-deinit-without-inert-reset`, `self-undefined-after-destroy`,
  `return-borrowed-payload`
- Lifecycle / sibling consistency: `reset-skips-pooled-resource-release`,
  `missing-deinit-on-composed-owner`, `owned-field-no-outer-cleanup`,
  `deinit-order-violates-construction-dep`,
  `defer-and-errdefer-free-overlap`, `move-out-without-restore`
- Concurrency / hardening: `publish-then-touch-self`,
  `assert-on-untrusted-input`

## Suppressions

```zig
buf[idx - 1] // zbc-disable-line: index-minus-one-without-zero-guard

// zbc-disable-next-line: heap-use-after-free
_ = ptr;

_ = val; // zbc-disable-line: *   (suppress all rules on this line)
```

## Acknowledgements

- [ZLS](https://github.com/zigtools/zls) — type-resolution internals
  (`DocumentStore`, `InternPool`, `Analyser`) extracted and adapted into
  `src/type_engine/` as zbc's embedded type engine.  Not imported as a
  package; vendored and modified in-tree.
