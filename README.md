# zbc

Region/lifetime escape analyzer for Zig.  Currently lives in the
ez monorepo at `zbc/`; designed for extraction to its own repo
(phase 45) once it stabilizes.

## What it does

Two analysis modes on Zig source:

1. **Layer 1 — annotation hygiene** (`zbc file.zig`).  Lints
   that public functions touching lifetime-bearing types
   (`NodeIndex`, slices borrowed from Ast source, arena allocators)
   carry the required `///` doc-comment annotations.

2. **Layer 2 — escape analysis** (`zbc --escape file.zig`).
   Lowers each function to a CFG, tracks per-local origins
   (`.arena`, `.ast`, `.ast_node`), and reports violations of
   user-declared invariants:
   - **#1**: A NodeIndex from Ast A must only flow back into A.
   - **#2**: A slice borrowed from an Ast's source buffer must
     not outlive that Ast.
   - **#5**: After parse completion, the Ast is read-only — any
     `@mutates_ast` method invalidates derived caches.
   - (#3 thread-arena, #4 pass-tagged IDs scaffolded but need
     inter-procedural extensions to be useful.)

## Annotation vocabulary

```zig
/// @returns owned                       — caller owns the result
/// @returns borrowed_from(<param>)      — return borrows from a param
/// @returns node_index_of(<param>)      — return is a NodeIndex tagged with param's Ast
/// @returns ast                         — return is a fresh Ast value

/// @takes node_index_of(<param>)        — NodeIndex args must match param's Ast
/// @takes node_index_any                — opt-out: any-Ast NodeIndex OK

/// @mutates_ast                         — method mutates receiver (or args[0])
/// @mutates_ast(<param>)                — method mutates the named param
```

## Project portability

ez-specific strings live in `Config` (config.zig):

```zig
pub const Config = struct {
    ast_type_name: []const u8 = "Ast",
    ast_init_patterns: []const []const u8 = &.{"Ast.parse"},
    arena_init_patterns: []const []const u8 = &.{"ArenaAllocator.init"},
    arena_kill_patterns: []const []const u8 = &.{".deinit("},
    thread_join_patterns: []const []const u8 = &.{".join("},
};
```

Downstream projects construct their own `Config` and pass it to
`analyzeEscape`.  The historical ez behavior lives at `DefaultConfig`.

## Standalone use

```sh
cd zbc
zig build test            # 136 tests
zig build run -- --escape path/to/file.zig
```

## Library use from another Zig project

`build.zig.zon`:

```zig
.dependencies = .{
    .zbc = .{ .path = "../path/to/zbc" },  // or .url + .hash
},
```

`build.zig`:

```zig
const zbc_dep = b.dependency("zbc", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zbc", zbc_dep.module("zbc"));
```

Your code:

```zig
const zbc = @import("zbc");

var cache = zbc.Cache.init(gpa, io);
defer cache.deinit();
const problems = try zbc.analyzeEscape(
    gpa, io, path, &cache, &zbc.DefaultConfig,
);
defer zbc.freeProblems(gpa, problems);
```

## Layout

```
zbc/
├── build.zig            – module + CLI build
├── build.zig.zon        – package manifest
├── lib.zig              – public API surface
├── main.zig             – CLI shell
├── config.zig           – project-tunable knobs
├── cfg.zig              – Zig AST → CFG lowering
├── abstract_state.zig   – Origin / ArenaId / ThreadContext
├── transfer.zig         – per-Stmt state transitions
├── analyzer.zig         – worklist fixed-point
├── annotations.zig      – @returns / @takes / @mutates_ast parser
├── imports.zig          – @import extractor
├── remote_resolver.zig  – cross-file annotation cache
├── problem.zig          – diagnostic type
└── rules/               – Layer-1 annotation-hygiene rules
```

## Status

Research-stage, used in production on one codebase (ez).  Phases
1-44 of the dev log document the build-up; phase 45 will extract
to its own repo.
