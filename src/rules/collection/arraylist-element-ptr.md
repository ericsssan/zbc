# arraylist-element-ptr

`const p = &list.items[i];` borrows a pointer into the list's backing
allocation.  A later receiver-matched mutation (`append`, `ensureTotal`,
`insert`, …) may reallocate that storage, leaving `p` dangling into
freed memory.

## Example (fires)

    const dep = &lockfile.deps.items[dep_id];
    try enqueue(dep);                     // may grow lockfile.deps
    use(dep.behavior);                    // ← use after free

## Fix

Copy the element to the stack before taking its address:

    const dep = lockfile.deps.items[dep_id];
    try enqueue(&dep);
    use(dep.behavior);

## Real-world instances

- oven-sh/bun#29483 — a dependency element pointer was held across
  `Lockfile.Package.fromNPM`, which grew `buffers.dependencies`;
  the later `behavior` read was a use-after-poison (ASAN).
