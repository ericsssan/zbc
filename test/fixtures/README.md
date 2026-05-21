# Test fixtures

Synthetic Zig sources demonstrating the canonical bug shape (and
control variants) for each rule.  Each file has both a "fires" case
and at least one "doesn't fire" control.

The fixtures double as integration-test inputs: run
`./zig-out/bin/zbc test/fixtures/<rule>.zig` to verify the rule
catches the synthetic bug.

## Mapping to rule modules

PR references throughout the codebase use the GitHub shorthand
`<owner>/<repo>#<number>` so that future fixtures from other Zig
repos (TigerBeetle, Zig itself, etc.) stay unambiguous next to
Bun's.

| Fixture | Rule | PR |
|---|---|---|
| `partial_union_write.zig` | `partial-union-write` | [oven-sh/bun#29422](https://github.com/oven-sh/bun/pull/29422) |
| `aliased_heap_dupe.zig` | `aliased-heap-dupe` | [oven-sh/bun#29910](https://github.com/oven-sh/bun/pull/29910) |
| `clobbered_by_struct_reset.zig` | `clobbered-by-struct-reset` | [oven-sh/bun#29854](https://github.com/oven-sh/bun/pull/29854) |
| `realloc_byte_count.zig` | `realloc-byte-count` | [oven-sh/bun#29452](https://github.com/oven-sh/bun/pull/29452) |
| `asymmetric_field_free.zig` | `asymmetric-field-free` | [oven-sh/bun#29853](https://github.com/oven-sh/bun/pull/29853) |
| `missing_errdefer_between_tries.zig` | `missing-errdefer-between-tries` | [oven-sh/bun#30169](https://github.com/oven-sh/bun/pull/30169) |
| `free_then_try_realloc.zig` | `free-then-try-realloc` | [oven-sh/bun#29968](https://github.com/oven-sh/bun/pull/29968) |
| `free_then_try_realloc_mysql.zig` | `free-then-try-realloc` (faithful MySQL repro, no `#`-private fields) | [oven-sh/bun#29968](https://github.com/oven-sh/bun/pull/29968) |
| `destroy_after_deinit_in_loop.zig` | `destroy-after-deinit-in-loop` | [oven-sh/bun#29879](https://github.com/oven-sh/bun/pull/29879) |
| `dead_errdefer_in_result_fn.zig` | `dead-errdefer-in-result-fn` | [oven-sh/bun#27706](https://github.com/oven-sh/bun/pull/27706) |
| `duplicate_errdefer.zig` | `duplicate-errdefer` | [tigerbeetle/tigerbeetle#2700](https://github.com/tigerbeetle/tigerbeetle/pull/2700) |
| `overwrite_without_deinit.zig` | `overwrite-without-deinit` | [oven-sh/bun#28633](https://github.com/oven-sh/bun/pull/28633), [oven-sh/bun#29864](https://github.com/oven-sh/bun/pull/29864) |
| `stack_fallback_escape.zig` | `stack-fallback-escape` | [ghostty-org/ghostty#9885](https://github.com/ghostty-org/ghostty/pull/9885) |
| `unreleased_refs_on_error.zig` | `unreleased-refs-on-error` | hexops/mach `sysgpu/vulkan.zig:1887` (mined; no PR) |
| `hashmap_getptr_rehash.zig` | `hashmap-getptr-rehash` | Zig std `HashMap` pointer-stability footgun (canonical class, no specific PR) |
| `arraylist_items_slice.zig` | `arraylist-items-slice` | Zig std `ArrayList.items` pointer-stability footgun (canonical class, no specific PR) |
| `fd_write_after_close.zig` | `fd-write-after-close` | POSIX/Windows file-handle use-after-close (canonical class, no specific PR) |
| `slice_of_arena_into_heap.zig` | `slice-of-arena-into-heap` | arena-allocated slice stored into a non-arena container (canonical class, no specific PR) |
| `free_without_null_then_check.zig` | `free-without-null-then-check` | [oven-sh/bun#30148](https://github.com/oven-sh/bun/pull/30148), [oven-sh/bun#30176](https://github.com/oven-sh/bun/pull/30176), [oven-sh/bun#29983](https://github.com/oven-sh/bun/pull/29983), [oven-sh/bun#29988](https://github.com/oven-sh/bun/pull/29988) |
| `tagged_union_retag_with_old_payload_read.zig` | `tagged-union-retag-with-old-payload-read` | [tigerbeetle/tigerbeetle#3317](https://github.com/tigerbeetle/tigerbeetle/pull/3317), [tigerbeetle/tigerbeetle#2200](https://github.com/tigerbeetle/tigerbeetle/pull/2200) |
| `union_deinit_without_inert_reset.zig` | `union-deinit-without-inert-reset` | [ghostty-org/ghostty#2257](https://github.com/ghostty-org/ghostty/pull/2257), [ghostty-org/ghostty#8307](https://github.com/ghostty-org/ghostty/pull/8307) |
| `self_undefined_after_destroy.zig` | `self-undefined-after-destroy` | [tigerbeetle/tigerbeetle#2687](https://github.com/tigerbeetle/tigerbeetle/pull/2687) |

## Re-fetching the actual pre-merge buggy files

The actual buggy files from each PR are too large to bundle (5–8k
lines each).  To replay any of them against zbc:

```bash
REPO=oven-sh/bun
PR=29422
BASE=$(gh pr view "$PR" --repo "$REPO" --json baseRefOid -q .baseRefOid)
FILE=src/http/Decompressor.zig    # adjust per PR
curl -sL "https://raw.githubusercontent.com/$REPO/$BASE/$FILE" -o /tmp/buggy.zig
./zig-out/bin/zbc /tmp/buggy.zig
```

Each commit message documents the file paths PR-by-PR.

## Unit tests

The synthetic patterns here are also encoded as inline `test "…"`
blocks in their respective rule modules (e.g. `realloc_byte_count.zig`).
Those run as part of `zig build test`; this directory's primary
role is documentation / integration smoke-testing.
