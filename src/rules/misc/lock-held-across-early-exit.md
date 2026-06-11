# lock-held-across-early-exit

A lock is acquired with `<recv>.lock()` and released later by
`<recv>.unlock()`, but a `return` or `try` sits between the two — so an
early/error exit can leave the function with the lock still held. The
next thread to acquire that lock then deadlocks.

```zig
m.lock();
const v = try parse(x);   // on error: returns WITH the lock held
m.unlock();
return v;

m.lock();
if (bad) return error.X;  // early return skips the unlock below
work();
m.unlock();
```

## Fix

Release on every path with `defer`:

```zig
m.lock();
defer m.unlock();
const v = try parse(x);
return v;
```

A `defer <recv>.unlock()` immediately after the lock covers normal, error,
and early-return exits, so it suppresses this rule.

## What does *not* fire

- `m.lock(); defer m.unlock(); …` — the safe idiom.
- An early path that unlocks before it exits
  (`if (bad) { m.unlock(); return; }`).
- A function that locks but never unlocks — it hands the lock to its
  caller (a deliberate lock/unlock split); this rule does not flag it, to
  avoid a false positive.
- Straight-line `lock(); …; unlock();` with no `return`/`try` between.

## Why it matters

`std.Thread.Mutex` / `RwLock` have no ownership tracking; a lock leaked on
an error path is a latent deadlock that only triggers under the failure
condition, making it easy to miss in testing. `defer` makes release
exit-path-independent.
