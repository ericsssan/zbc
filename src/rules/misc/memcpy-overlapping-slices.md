# memcpy-overlapping-slices

`@memcpy(base[a..b], base[c..d])` with both arguments derived from the
same base slice may overlap.  Zig treats aliased `@memcpy` arguments as
a safety violation: it panics in Debug/ReleaseSafe and is undefined
behaviour in ReleaseFast.

## Example (fires)

    @memcpy(input[0..n], input[offset..][0..n]);

## Fix

Use a copy that tolerates overlap:

    std.mem.copyForwards(u8, input[0..n], input[offset..][0..n]);

## Real-world instances

- ziglang/zig#21447 — `std.compress.lzma` copied a decompressed window
  onto itself.
- ziglang/zig#17400 — `RingBuffer` slice-aliased `@memcpy`.
- ziglang/zig#19289 — same pattern in the xz block decoder.
