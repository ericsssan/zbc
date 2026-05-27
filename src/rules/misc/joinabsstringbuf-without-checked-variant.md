# joinabsstringbuf-without-checked-variant

`joinAbsStringBuf(...)` — this unchecked variant does not detect buffer overflow and silently writes past the end of fixed-size stack or threadlocal buffers when the normalized path length exceeds the buffer size. Use `joinAbsStringBufChecked` instead, which falls back to a heap allocation on overflow.

## What the rule checks

The rule fires on any call to `joinAbsStringBuf(`. Calls to `joinAbsStringBufChecked` are the safe alternative and do not fire.

## Why it matters

`joinAbsStringBuf` calls `normalizeStringGenericTZ` internally, which uses `@memcpy` to write into the output buffer. When the normalized path is longer than the provided buffer, `normalizeStringGenericTZ` writes past the end — corrupting adjacent stack or threadlocal memory with no error signal.

File paths are user-controlled. On most filesystems, paths can reach `PATH_MAX` (~4096 bytes), and the normalized form (with resolved `..` components and symlinks expanded) can be even longer. Any fixed-size buffer smaller than the maximum possible normalized path length is a potential OOB write.

`joinAbsStringBufChecked` detects the overflow condition and returns a heap-allocated `bun.String` fallback, making it safe for paths of any length.

## Real-world instance

**oven-sh/bun#28585** (pathToFileURL): `joinAbsStringBuf` was called with a 4096-byte threadlocal `join_buf`. Long relative paths (> 4 KB) caused `normalizeStringGenericTZ` to `@memcpy` past the end of the buffer, silently corrupting adjacent threadlocal state. The fix switched to `joinAbsStringBufChecked` which handles overflow with a heap fallback.

## Fix

```zig
// Instead of:
const url = joinAbsStringBuf(&join_buf, parts, .auto);

// Use the checked variant:
const url = joinAbsStringBufChecked(&join_buf, parts, .auto, allocator);
```
