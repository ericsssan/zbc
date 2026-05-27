# usize-geq-zero-loop

**Severity:** error  
**Category:** misc / integer / bounds  
**Tier:** 1 (token walk)

## What this checks

`while (i >= 0 ...)` where `i` is of type `usize` (or any other unsigned
integer).  Since `usize` is unsigned, the condition `i >= 0` is always `true`
— the loop never terminates via this exit condition.  The typical intent is a
reverse scan that should stop when the index wraps past zero; the correct
approach is `while (i > 0)` (pre-decrement after the body) or restructuring
the loop to use `i + 1 > 0` / `i != 0`.

In Zig the `>=` comparison on an unsigned value is accepted without a
compiler warning, so the bug is silent.  At runtime the loop body continues
to execute even after `i` wraps from `0` to `maxInt(usize)` on `i -= 1` —
or the loop termination condition in `: (i -= 1)` causes a debug-build panic
on the arithmetic underflow.

## Example (fires)

```zig
// i is usize; condition is always true
var i: usize = slice.len - 1;
while (i >= 0) : (i -= 1) {
    //  ^^^^^^ always true — infinite loop / underflow panic
    if (slice[i] == '\\') break;
}
```

## Fix

Use a strictly-positive guard or restructure to avoid underflow:

```zig
// Option 1: check before decrement
var i = slice.len;
while (i > 0) {
    i -= 1;
    if (slice[i] == '\\') break;
}

// Option 2: saturating subtract (exits when i wraps to maxInt)
var i: usize = slice.len -| 1;
while (i < slice.len) : (i -|= 1) { ... }
```

## Real-world instances

- oven-sh/bun#11491 — `src/glob.zig` reverse backslash scan:
  `var i: usize = idx -| 1; while (i >= 0 and potential_pattern[i] == '\\') : (i -= 1)`
  The condition `i >= 0` is always true for `usize`; the fix restructured to
  `while (i > 0 and potential_pattern[i - 1] == '\\') : (i -= 1)`.
- oven-sh/bun#24561 — `src/install/hosted_git_info.zig` reverse path scan:
  `pi` (a `usize`) underflows when the guarded index `pi - 1` hits 0 because
  the `>= 0` condition did not protect the index access.
