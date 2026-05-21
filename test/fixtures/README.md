# Test fixtures

Synthetic Zig sources demonstrating the canonical bug shape (and
control variants) for each rule.  Each file has both a "fires" case
and at least one "doesn't fire" control.

The fixtures double as integration-test inputs: run
`./zig-out/bin/zbc test/fixtures/<rule>.zig` to verify the rule
catches the synthetic bug.

## Mapping to rule modules

| Fixture | Rule | PR |
|---|---|---|
| `partial_union_write.zig` | `partial-union-write` | [#29422](https://github.com/oven-sh/bun/pull/29422) |
| `aliased_heap_dupe.zig` | `aliased-heap-dupe` | [#29910](https://github.com/oven-sh/bun/pull/29910) |
| `clobbered_by_struct_reset.zig` | `clobbered-by-struct-reset` | [#29854](https://github.com/oven-sh/bun/pull/29854) |
| `realloc_byte_count.zig` | `realloc-byte-count` | [#29452](https://github.com/oven-sh/bun/pull/29452) |
| `asymmetric_field_free.zig` | `asymmetric-field-free` | [#29853](https://github.com/oven-sh/bun/pull/29853) |
| `missing_errdefer_between_tries.zig` | `missing-errdefer-between-tries` | [#30169](https://github.com/oven-sh/bun/pull/30169) |
| `free_then_try_realloc.zig` | `free-then-try-realloc` | [#29968](https://github.com/oven-sh/bun/pull/29968) |
| `free_then_try_realloc_mysql.zig` | `free-then-try-realloc` (faithful MySQL repro, no `#`-private fields) | [#29968](https://github.com/oven-sh/bun/pull/29968) |
| `destroy_after_deinit_in_loop.zig` | `destroy-after-deinit-in-loop` | [#29879](https://github.com/oven-sh/bun/pull/29879) |
| `dead_errdefer_in_result_fn.zig` | `dead-errdefer-in-result-fn` | [#27706](https://github.com/oven-sh/bun/pull/27706) |

## Re-fetching the actual pre-merge buggy files

The actual buggy files from each PR are too large to bundle (5–8k
lines each).  To replay any of them against zbc:

```bash
PR=29422
BASE=$(gh pr view "$PR" --repo oven-sh/bun --json baseRefOid -q .baseRefOid)
FILE=src/http/Decompressor.zig    # adjust per PR
curl -sL "https://raw.githubusercontent.com/oven-sh/bun/$BASE/$FILE" -o /tmp/buggy.zig
./zig-out/bin/zbc /tmp/buggy.zig
```

Each commit message documents the file paths PR-by-PR.

## Unit tests

The synthetic patterns here are also encoded as inline `test "…"`
blocks in their respective rule modules (e.g. `realloc_byte_count.zig`).
Those run as part of `zig build test`; this directory's primary
role is documentation / integration smoke-testing.
