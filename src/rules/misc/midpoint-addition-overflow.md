# midpoint-addition-overflow

`(a + b) / 2` computes a binary-search midpoint by adding both bounds
first.  When both are near the type's maximum, the addition overflows
before the division, producing a wrapped or wrong midpoint.

## Example (fires)

    const mid = (left + right) / 2;        // ← overflows for large bounds

## Fix

Subtract first:

    const mid = left + (right - left) / 2;

## Real-world instances

- ziglang/zig#20029 — `std.sort.upperBound` overflowed for bounds near
  `maxInt(usize)`.
- ziglang/zig#18718 — same shape in `lowerBound` / `equalRange`.
