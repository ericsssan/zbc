# interior-pointer-destroy

Calling a destructor (`destroy` / `deinit` / `free` / etc.) on a
pointer that is NOT the result of `allocator.create()` is
undefined behavior under typical allocators.  The destructor
internally calls `allocator.destroy(self)`, which the allocator's
bookkeeping expects to be a fresh allocation it produced — passing
an interior pointer (`&array[i]`, a for-loop pointer-capture into
a container, etc.) corrupts the allocator's metadata or frees the
wrong allocation entirely.

## Example

Incorrect — `result` is a pointer INTO `entries.items`, not a
fresh allocation:

    for (entries.items) |*result| {
        result.destroy();           // ← UB; interior pointer
    }
    entries.deinit();                // ← may then double-free

zbc reports the destroy call.  The cascading double-free (when
`entries.deinit()` also frees the same backing) shows as a
separate `heap-double-free` finding.

Fix — let the container own the lifecycle:

    for (entries.items) |result| {
        // Don't destroy from interior; consume the element's
        // fields directly, then let entries.deinit clean up.
    }
    entries.deinit();

## When this might be a false positive

- The destructor doesn't actually call `allocator.destroy(self)`
  — it only releases sub-fields and treats `self` as borrow.
  zbc can't tell from the call site; if your destructor is in
  fact safe for interior pointers, rename it to something that
  signals that (and out of `destroy` / `deinit` / `die` /
  `release` / `free` / `close` / `dispose`), or annotate the
  method to opt out.
- The container in question doesn't actually own heap storage
  for its elements (e.g. a stack array).  zbc fires on the
  syntactic shape; the false positive should be rare since the
  pattern is unusual outside of heap-backed containers.

## Related

- `heap-double-free`: the typical follow-on when interior-pointer
  destroy frees a container's backing and then the container
  later deinits.
