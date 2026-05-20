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

## Borrow-tracking annotations

When the use happens through a borrow rather than the freed pointer
itself, zbc relies on annotations to connect the borrow back to the
owner.

- `/// @takes ownership(<param>)` on a fn marks the call as a
  free of the named param.  Without it, `owner.die()` cannot kill
  owner's storage and downstream reads are not flagged.
- `/// @borrowed` on a struct field marks the field's storage as
  owned by the containing struct.  Reading or copying the field
  yields a borrow tied to the parent's lifetime; a later
  `@takes(0)` call on the parent invalidates the borrow.  Without
  the annotation, zbc treats field reads as independent values
  (no propagation) to avoid false positives on the many fields
  that ARE independent — `arr.len`, `obj.tag`, etc.

Example:

    const Owner = struct {
        /// @borrowed
        data: []u8 = &.{},

        /// @takes ownership(self)
        pub fn die(self: *Owner) void { /* ... */ }
    };

    var owner: Owner = .{};
    const borrowed = owner.data; // borrowed origin tied to owner
    owner.die();
    _ = borrowed;                // ← heap-use-after-free fires

## Related

- `heap-double-free`: freeing the same pointer twice.
- `arena-use-after-kill`: same shape, but the resource is an arena
  rather than a single heap allocation.
