# heap-use-after-free

Reading or returning a heap pointer after the corresponding `free` /
`destroy` call.  The value's storage has been returned to the
allocator; reading it is undefined behavior.

## Example

Incorrect — `buf` is read after free:

    const buf = try allocator.alloc(u8, 32);
    allocator.free(buf);
    process(buf);                       // ← use after free

Fix — perform all reads before the free, or assign a fresh value
through the same name before re-use:

    const buf = try allocator.alloc(u8, 32);
    process(buf);
    allocator.free(buf);

## When this might be a false positive

- Conditional free + use on disjoint paths.  zbc tracks state per
  basic block and joins conservatively at merges; one branch
  freeing and another using can produce a join state that flags the
  use.  Reshape the code so the free and use are not joined.
- Re-allocation through a path zbc can't classify.  A fresh
  `buf = alloc(...)` clears the prior free, but if the rebind goes
  through an unrecognised builder method, the prior free state may
  persist.  Naming the constructor `init`/`create`/`new`/`open`
  helps the classifier recognise the fresh allocation.

## Related

- `heap-double-free`: freeing the same pointer twice.
- `arena-use-after-kill`: same shape, but the resource is an arena
  rather than a single heap allocation.
