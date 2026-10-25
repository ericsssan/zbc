# cmpxchgweak-orelse-break

`@cmpxchgWeak` returns `?T` where `null` means **success** and
`Some(current)` means **failure**.  Writing `cmpxchgWeak(...) orelse
break` therefore exits the loop on success, skipping the work the
successful exchange was supposed to unlock.

## Example (fires)

    while (true) {
        const prev = sync.cmpxchgWeak(expected, next, .monotonic, .monotonic)
            orelse break;                 // ← exits on success
        expected = prev;                  // retry path never runs
        break;
    }

## Fix

Branch on the payload, which is present only on failure:

    while (true) {
        if (sync.cmpxchgWeak(expected, next, .monotonic, .monotonic)) |actual| {
            expected = actual;
            continue;
        }
        spawnWorker();
        break;
    }

## Real-world instances

- oven-sh/bun#28940 — the ThreadPool spawn loop used
  `cmpxchgWeak(...) orelse break`, so it exited on success and never
  spawned threads while still counting phantom slots.
