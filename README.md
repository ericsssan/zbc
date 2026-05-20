# zbc

A borrow checker for Zig, inspired by Rust's.

## Rules

| Rule | Catches |
|---|---|
| `heap-use-after-free` | Reading a heap pointer after `free` / `destroy` |
| `heap-double-free` | Freeing the same heap pointer twice |
| `arena-use-after-kill` | Reading an arena-borrowed value after the arena's `deinit` |
| `arena-escape` | Returning a value borrowed from a function-local arena |
| `stack-escape` | Returning a pointer to a function-local stack variable |
| `use-undefined` | Reading a value that is still `undefined` |
| `require-borrowed-from` | Public borrowed-shape return without `@returns borrowed_from(...)` |

Cross-function chains, struct-literal aliases, stack-owner borrows
(`var o = ...; const x = &o.field; o.die(); use(x)`), and
`@borrowed`-annotated field copies are all tracked.

## Usage

```sh
zig build -Doptimize=ReleaseFast
zbc path/to/file.zig
zbc --format=compact path/to/file.zig    # grep-friendly
zbc --list-rules
zbc --explain heap-use-after-free
```

Exit 0 if clean, 1 if problems found.  Default output is Rustc-style
with caret + secondary span for the free / kill site.

## Annotations

Most analysis is inference-driven.  Annotations fill the gaps where
source shape is ambiguous:

```zig
/// @returns owned | borrowed_from(<param>) | owns_locals | heap
/// @takes ownership(<param>)
/// @borrowed                              (on a struct field)
```

Borrow example:

```zig
const Owner = struct {
    /// @borrowed
    data: []u8 = &.{},

    /// @takes ownership(self)
    pub fn die(self: *Owner) void { /* ... */ }
};

var owner: Owner = .{};
const x = owner.data;       // borrow of owner
owner.die();
_ = x;                      // → heap-use-after-free
```

## Library use

```zig
const zbc = @import("zbc");

const problems = try zbc.analyzeEscape(
    gpa, io, path, /*cache=*/null, &zbc.DefaultConfig,
);
defer zbc.freeProblems(gpa, problems);
```
