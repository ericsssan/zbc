# stale-annotation

A function carries a `/// @returns owned`, `/// @returns heap`, or
`/// @returns borrowed_from(<param>)` doc-comment annotation, but the
body's inferred behavior CONTRADICTS the annotation.

## Why it matters

zbc is migrating from author-asserted lifetime annotations to pure
inference + an in-source suppression mechanism (`// zbc-disable-line:
<rule-id>`).  While both systems coexist, mismatches are real bugs:
the annotation lies about what the body does, which corrupts every
downstream consumer's analysis.

The end state is "no annotations except suppression."  Until then,
this rule surfaces lies so they can be fixed (or the annotation
deleted).

## Bad

```zig
/// @returns owned
pub fn text(self: *Foo) []const u8 {
    return self.buf;  // actually a borrow of self
}
```

```zig
/// @returns borrowed_from(self)
pub fn make(self: *Foo, gpa: std.mem.Allocator) ![]u8 {
    _ = self;
    return try gpa.alloc(u8, 8);  // actually a fresh heap alloc
}
```

```zig
/// @returns borrowed_from(a)
pub fn pick(a: *Foo, b: *Foo) []const u8 {
    _ = a;
    return b.buf;  // borrows b, not a
}
```

## Good

```zig
// Match the annotation to the body, or delete the annotation:
pub fn text(self: *Foo) []const u8 {
    return self.buf;  // inference will classify as borrowed_from(self)
}
```

If the inference is genuinely wrong on a real-world case, suppress
locally:

```zig
/// @returns owned
// zbc-disable-line: stale-annotation
pub fn weird_case(self: *Foo) []const u8 {
    return self.cached orelse self.compute();
}
```

## Cases that don't fire (conservative)

- Inference returned `.unknown` — the rule can't disprove the
  annotation.
- `/// @returns owns_locals` — explicit escape-hatch annotation; the
  author is asserting something inference can't prove.
- `@returns owned` and inference says `.plain` — value-typed returns
  where the annotation is redundant but not wrong.

## When this rule becomes obsolete

Once the annotation parsing path is deleted from `annotations.zig`
(see the `fn_summary.zig` migration), no fn will ever carry an
annotation, so this rule becomes a permanent no-op and can be
deleted.
