# slice-write-at-len

`buf[buf.len] = value` writes exactly one past the last valid index.
Valid indices are `0..len-1`; the write panics in Debug/ReleaseSafe and
is undefined behaviour in ReleaseFast.  The same holds for a field form
such as `obj.field[obj.field.len] = value`.

## Example (fires)

    output.items[output.items.len] = 0;    // ← one past the end

## Fix

Append instead, so capacity is checked:

    try output.append(gpa, 0);

## Suppression

Form `x[x.len] = …` is suppressed when `x` is a sub-slice of a longer
buffer (`outer.field[field.len] = …`), and both forms are suppressed
around `allocSentinel` / sentinel array types, where index `len` is the
sentinel slot by construction.

## Real-world instances

- oven-sh/bun#29982 — `toUTF16Alloc` wrote the null terminator one past
  the end of the ArrayList buffer.
