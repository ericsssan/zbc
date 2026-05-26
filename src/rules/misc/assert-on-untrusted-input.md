# assert-on-untrusted-input

`assert(<expr>)` inside a parser / decoder fn where `<expr>`
references a parameter that looks like untrusted external input
(a `[]const u8` buffer, a `*Message` / `*Block` / `*Header`
pointer, or similar).  Crafted input trips the assert → process
panic / DoS.

TigerStyle: asserts encode INTERNAL invariants known to hold at
that program point.  Values from a network packet, file, or peer
block are EXTERNAL and must be validated explicitly:

```zig
if (!<cond>) return error.Invalid<X>;
```

never:

```zig
assert(<cond>);
```

## Why this matters

The bug class is a DoS vector: a malformed file or a hostile
network packet can trip an `assert` written assuming the
malformed-but-syntactically-valid case can't occur.  Under
`ReleaseSafe` (TigerBeetle's production mode) the assert panics
and kills the process.  Under `ReleaseFast` the assert is removed
and the malformed input causes silent corruption (buffer
underflow, out-of-bounds index, wrong-state reads).

Both modes are bad.  The right shape is explicit validation that
returns a typed error.

## Canonical bugs

**tigerbeetle/tigerbeetle#3709** (`src/multiversion.zig` — Mach-O fat-arch parser):

```zig
- assert(body_offset_aarch64 == null and body_size_aarch64 == null);
+ if (body_offset_aarch64 != null) return error.InvalidMachoDuplicate;
```

**tigerbeetle/tigerbeetle#3726** (`src/cdc/amqp/protocol.zig` — AMQP frame decoder):

```zig
+ if (initial_index + frame_size < self.index) return error.Unexpected;
  // ...later slice computation that would have underflowed silently
```

**tigerbeetle/tigerbeetle#2980** (`src/vsr/grid.zig` — disk block release-value check):

The assert was moved INSIDE the branch that matches a queued read
(i.e., gated on a verified-local invariant) rather than firing
unconditionally on a network block.

## Why the detector is precise

- Strict "untrusted input" signal: the fn must have at least one
  parameter whose declared type starts with `[` (a slice or
  array type — `[]const u8`, `[]u8`, `[*]const u8`,
  `[N]u8`, `[:0]const u8`, etc.).  Structured wrappers like
  `*Message`, `Decoder.Header`, `*Block` are EXCLUDED — they're
  too commonly used for internally-constructed values that the
  enclosing code already validated.
- Fire ONLY when the assert expression mentions one of the
  slice-typed parameter names.  Internal asserts on `self`/
  other-state aren't flagged.

## Limitations (deliberate)

- Excludes structured-wrapper inputs.  A `decode_frame(frame:
  *Frame)` won't fire even though `frame` may have come from
  the network — because tracking that requires call-site
  analysis.  Real TigerBeetle parsers do pass typed wrappers
  around after a CHECKSUM-validated initial parse, so this is
  often the right call.
- Doesn't track flow through local variables (`const n =
  buffer[0]; assert(n < 16);` doesn't fire on `assert(n)`).
- Doesn't recognize project-specific assertion helpers
  (`my_assert`, `expect`, `verify`) — only stdlib's `assert`.
