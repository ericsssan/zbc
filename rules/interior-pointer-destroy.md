# interior-pointer-destroy

Calling a cleanup-shape method (`deinit` / `close` / `dispose` /
`release` / `deref` / `unref` / `finalize` / `removeRef`) on a
pointer that is NOT the result of `allocator.create()` is
suspect.  Cleanup methods typically assume the receiver IS a
fresh heap allocation OR that the receiver's storage is exclusive
to the caller; calling one on an interior pointer (`&array[i]`,
a for-loop pointer-capture into a container, etc.) at minimum
violates the convention, and when the method actually calls
`allocator.destroy(self)` corrupts the allocator's metadata or
frees the wrong allocation entirely.

zbc fires on the **pattern** (cleanup-named method on an interior
pointer) — not on proven destruction.  Whether the method actually
calls `allocator.destroy(self)` requires inferring takes-ownership
semantics that often span files / generic instantiations.  The
pattern is the suspect: even when the method just releases internal
fields, calling it on an interior pointer signals a likely
ownership-model confusion.

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

- The cleanup method is genuinely safe for interior pointers
  (e.g. it only releases shared sub-resources without freeing
  storage).  The pattern is still worth a second look — if the
  method really doesn't take ownership of self, consider
  renaming it to something OUT of `deinit` / `close` / `dispose`
  / `release` / `deref` / `unref` / `finalize` / `removeRef`, or
  suppressing the line with `// zbc-disable-line: interior-pointer-destroy`.
- The container's element storage is itself stack-only (e.g. a
  comptime-known fixed array) — the "interior pointer" framing
  doesn't apply since there's no allocator involved.

## Related

- `heap-double-free`: the typical follow-on when interior-pointer
  destroy frees a container's backing and then the container
  later deinits.
