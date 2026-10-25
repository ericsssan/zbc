# arena-allocator-free-noop

`.allocator().free(x)` on an allocator obtained from an arena is a
runtime no-op: `ArenaAllocator` has no per-allocation free.  The call
gives a false impression that the buffer was released, and later reads
of that "freed" buffer still observe live memory.  Memory is reclaimed
only when the arena itself is deinitialized.

## Example (fires)

    const tmp = try arena.allocator().dupe(u8, name);
    arena.allocator().free(tmp);          // ← no-op
    log.debug("{s}", .{tmp});             // still reads live memory

## Fix

Drop the `free` call and let the arena's `deinit` reclaim the memory.

## Real-world instances

- oven-sh/bun#29380 — `this.arena.allocator().free(name_matched_path)`
  was a no-op; a later log read the buffer as if ownership had moved.
