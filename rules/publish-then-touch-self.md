# publish-then-touch-self

`<chain>.<publish-method>(this);` (or `(self)`) where the chain or
method suggests concurrent / cross-thread dispatch — followed by
any further use of `this`/`self` in the same scope.  The consumer
thread may have freed `this` before the second access lands.

Concurrent dispatch is identified by:
- Method name containing `Concurrent`, `Thread`, `Cross`, `Async`,
  or being one of `postToMain` / `postTask` / `scheduleTask` /
  `spawn` / `dispatch`.
- Receiver chain containing `queue`, `pool`, `thread`,
  `cross_thread`, `concurrent`, `dispatcher`, `scheduler`,
  `work_pool` / `workPool` / `thread_pool` / `threadPool`.

## Why this matters

Once `this`/`self` has been handed to a different thread (via a
lock-free queue, a thread pool task slot, a cross-thread channel),
the consumer is free to run, complete, and FREE the object before
the publishing thread executes its next instruction.  Any further
read or method call on `this` from the publisher is a
cross-thread use-after-free.

The canonical Bun pattern (from oven-sh/bun#29128):

```zig
// BUGGY:
transpiler_store.queue.push(this);                                     // ← publish
vm.eventLoop().enqueueTaskConcurrent(jsc.ConcurrentTask.createFrom(transpiler_store));
// `this` (and via the previous publish, `transpiler_store`)
// may already have been freed by the worker thread.
```

The fix hoists all post-publish reads into LOCALS before the publish:

```zig
const vm = this.vm;
const transpiler_store = &vm.transpiler_store;
transpiler_store.queue.push(this);
// `this` is now untouchable — must not be accessed again.
vm.eventLoop().enqueueTaskConcurrent(jsc.ConcurrentTask.createFrom(transpiler_store));
```

## Why the detector is precise

- Two layered signals — method-name AND receiver-chain — keep the
  match tight.  `list.append(this)` (not concurrent) doesn't fire;
  `queue.push(this)` (concurrent) does.
- Argument must be EXACTLY `this` or `self` (bare identifier).
  `queue.push(self.field)` is a different shape (already covered
  by other rules or is benign — `self.field` is a sub-object whose
  lifetime may be tied to a different owner).
- Use-after detection is scope-bounded — past the enclosing `}`
  the rule doesn't continue.  No false positives from same-name
  identifiers in sibling scopes.

Limitations (deliberate):
- Doesn't track aliased publishes (`const x = this; queue.push(x);
  this.field;` — `this` aliased through `x`).
- Doesn't distinguish "publish that may not actually run on another
  thread" (e.g., synchronous deferred callbacks).
- Concurrency-receiver allowlist is narrow; project-specific
  channel/queue names won't match unless they contain one of the
  recognized tokens.
