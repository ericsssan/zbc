# clamp-wrong-direction

`@max(x, std.math.maxInt(T))` and `@min(x, std.math.minInt(T))` clamp
in the wrong direction.  The first forces the result to at least
`maxInt(T)` — above `T`'s range — so a downstream `@intCast` panics in
ReleaseSafe and overflows in ReleaseFast.  The second forces the result
to at most `minInt(T)`, so every value except `minInt(T)` fails the
cast.

## Example (fires)

    const n: u8 = @intCast(@max(size, std.math.maxInt(u8)));

## Fix

Clamp toward the range, not away from it:

    const n: u8 = @intCast(@min(size, std.math.maxInt(u8)));

## Real-world instances

- oven-sh/bun#29813 — `@intCast(@max(queueSize, std.math.maxInt(u8)))`
  forced every queue size in 0..254 to panic.
