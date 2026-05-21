//! Static catalog of rule docs, embedded at comptime.
//!
//! Each rule has a markdown explainer in `rules/<id>.md`.  This
//! module @embedFile's them so the binary is self-contained — no
//! runtime fs lookup needed for `--explain`.
//!
//! Adding a rule:
//!   1. Drop `rules/<new-id>.md` into the repo.
//!   2. Add a `Rule` entry below.
//!   3. (If it's a new analysis branch, also wire the rule_id
//!      through `transfer.zig` / the relevant pass.)

const std = @import("std");

pub const Rule = struct {
    /// Stable kebab-case identifier.  Also the markdown filename
    /// stem and the string emitted in diagnostics' `error[<id>]:`
    /// header.
    id: []const u8,
    /// One-line description.  Shown by `--list-rules`.
    title: []const u8,
    /// Full markdown explainer.  Shown by `--explain <id>`.
    body: []const u8,
};

pub const all = [_]Rule{
    .{
        .id = "heap-use-after-free",
        .title = "reading or returning a heap pointer after free",
        .body = @embedFile("rules/heap-use-after-free.md"),
    },
    .{
        .id = "heap-double-free",
        .title = "freeing the same heap pointer twice",
        .body = @embedFile("rules/heap-double-free.md"),
    },
    .{
        .id = "arena-use-after-kill",
        .title = "reading a value borrowed from an arena after the arena's deinit",
        .body = @embedFile("rules/arena-use-after-kill.md"),
    },
    .{
        .id = "arena-escape",
        .title = "returning a value borrowed from a function-local arena",
        .body = @embedFile("rules/arena-escape.md"),
    },
    .{
        .id = "stack-escape",
        .title = "returning a pointer to a function-local stack variable",
        .body = @embedFile("rules/stack-escape.md"),
    },
    .{
        .id = "use-undefined",
        .title = "reading a value that is still `undefined`",
        .body = @embedFile("rules/use-undefined.md"),
    },
    .{
        .id = "require-borrowed-from",
        .title = "public borrowed-shape return without a @returns borrowed_from() annotation",
        .body = @embedFile("rules/require-borrowed-from.md"),
    },
    .{
        .id = "allocator-mismatch",
        .title = "freeing with an allocator different from the one that allocated",
        .body = @embedFile("rules/allocator-mismatch.md"),
    },
    .{
        .id = "interior-pointer-destroy",
        .title = "calling a destructor on an interior pointer into a container's storage",
        .body = @embedFile("rules/interior-pointer-destroy.md"),
    },
    .{
        .id = "heap-leak",
        .title = "destructor of a heap-allocated type never frees `self`",
        .body = @embedFile("rules/heap-leak.md"),
    },
    .{
        .id = "partial-union-write",
        .title = "tagged-union literal with `try`/`catch return` in payload — tag is written before payload",
        .body = @embedFile("rules/partial-union-write.md"),
    },
    .{
        .id = "aliased-heap-dupe",
        .title = "dupe returns `T` by value with `var dup = this.*;` — heap-owning fields alias the source",
        .body = @embedFile("rules/aliased-heap-dupe.md"),
    },
    .{
        .id = "clobbered-by-struct-reset",
        .title = "`this.<X> = …;` then `this.* = StructLit{…}` without `.<X>` — heap pointer dropped to default",
        .body = @embedFile("rules/clobbered-by-struct-reset.md"),
    },
    .{
        .id = "realloc-byte-count",
        .title = "`allocator.realloc(slice, n * @sizeOf(T))` — Zig's realloc takes ELEMENT count, not bytes",
        .body = @embedFile("rules/realloc-byte-count.md"),
    },
    .{
        .id = "asymmetric-field-free",
        .title = "destructor handles some same-typed fields but omits others — the omitted ones leak",
        .body = @embedFile("rules/asymmetric-field-free.md"),
    },
    .{
        .id = "missing-errdefer-between-tries",
        .title = "`const X = try Type.method(…);` then another `try` with no `errdefer X.deinit();` — X leaks on the second error",
        .body = @embedFile("rules/missing-errdefer-between-tries.md"),
    },
    .{
        .id = "free-then-try-realloc",
        .title = "`free(X); X = try alloc(…);` without clearing X first — X dangles on alloc failure → double-free in `deinit`",
        .body = @embedFile("rules/free-then-try-realloc.md"),
    },
    .{
        .id = "destroy-after-deinit-in-loop",
        .title = "destructor loops `<h>.deinit();` over pointer-list items without `<allocator>.destroy(<h>);` — heap descriptors leak",
        .body = @embedFile("rules/destroy-after-deinit-in-loop.md"),
    },
    .{
        .id = "dead-errdefer-in-result-fn",
        .title = "`errdefer` in a fn returning a `Result(T)` tagged union (not `!T`) — never fires, cleanup silently leaks",
        .body = @embedFile("rules/dead-errdefer-in-result-fn.md"),
    },
    .{
        .id = "duplicate-errdefer",
        .title = "two `errdefer X.<cleanup>();` for the same receiver — cleanup runs twice on error → double-free / assert",
        .body = @embedFile("rules/duplicate-errdefer.md"),
    },
    .{
        .id = "overwrite-without-deinit",
        .title = "`this.field = X;` for a deinit-able field without prior `this.field.deinit();` — old value leaks",
        .body = @embedFile("rules/overwrite-without-deinit.md"),
    },
    .{
        .id = "stack-fallback-escape",
        .title = "value built on a `stackFallback(N, …)` allocator escapes the fn — points at caller's stack buffer",
        .body = @embedFile("rules/stack-fallback-escape.md"),
    },
    .{
        .id = "unreleased-refs-on-error",
        .title = "loop calls `<obj>.<addref>()` then a later `try` runs with no `errdefer` releasing — refs leak on error",
        .body = @embedFile("rules/unreleased-refs-on-error.md"),
    },
    .{
        .id = "hashmap-getptr-rehash",
        .title = "use of `<X>` after `<map>.put/remove/...(...)` — the borrow from `<map>.getPtr/getOrPut(...)` was invalidated",
        .body = @embedFile("rules/hashmap-getptr-rehash.md"),
    },
    .{
        .id = "arraylist-items-slice",
        .title = "use of `<X>` after `<list>.append/insert/...(...)` — the slice borrowed via `<list>.items` was invalidated by a realloc",
        .body = @embedFile("rules/arraylist-items-slice.md"),
    },
    .{
        .id = "fd-write-after-close",
        .title = "use of file handle `<X>` after `<X>.close()` — the fd is invalid; reads/writes go through a dangling fd",
        .body = @embedFile("rules/fd-write-after-close.md"),
    },
    .{
        .id = "slice-of-arena-into-heap",
        .title = "arena-allocated slice stored into a non-arena container — dangles when the local arena's deinit fires",
        .body = @embedFile("rules/slice-of-arena-into-heap.md"),
    },
    .{
        .id = "free-without-null-then-check",
        .title = "freed `<recv>.<field>` without reset — slot now dangles; later `if (<recv>.<field>) |h| use(h);` UAFs",
        .body = @embedFile("rules/free-without-null-then-check.md"),
    },
    .{
        .id = "tagged-union-retag-with-old-payload-read",
        .title = "reading `<path>.<OldTag>` while assigning `.{ .<NewTag> = ... }` to `<path>` — x86_64 backend may evaluate read after tag flip",
        .body = @embedFile("rules/tagged-union-retag-with-old-payload-read.md"),
    },
    .{
        .id = "union-deinit-without-inert-reset",
        .title = "switch arm deinit'd payload but didn't retag the union — idempotent reset/clear/end fn will double-free on next call",
        .body = @embedFile("rules/union-deinit-without-inert-reset.md"),
    },
    .{
        .id = "self-undefined-after-destroy",
        .title = "`<X>.* = ...` / `<X>.<field> = ...` after `<alloc>.destroy(<X>);` — write hits freed memory (TigerStyle order inverted)",
        .body = @embedFile("rules/self-undefined-after-destroy.md"),
    },
    .{
        .id = "missing-errdefer-on-out-param",
        .title = "`try <out>.<field>.<acquire>(...)` then later `try` with no `errdefer <out>.<field>.deinit(...)` — out-param leaks on error",
        .body = @embedFile("rules/missing-errdefer-on-out-param.md"),
    },
    .{
        .id = "reset-skips-pooled-resource-release",
        .title = "`deinit` releases pool/handle resources but sibling `reset` doesn't — callers using `reset` leak slots",
        .body = @embedFile("rules/reset-skips-pooled-resource-release.md"),
    },
    .{
        .id = "return-borrowed-payload",
        .title = "`return switch (...) { .<Tag> => |v| v, ... }` — bare payload return while sibling arm clones; borrowed value escapes caller's lifetime",
        .body = @embedFile("rules/return-borrowed-payload.md"),
    },
};

/// Look up a rule by id.  Returns null on unknown id so callers can
/// surface a useful error rather than panicking.
pub fn lookup(id: []const u8) ?*const Rule {
    for (&all) |*r| {
        if (std.mem.eql(u8, r.id, id)) return r;
    }
    return null;
}

// ── Tests ──────────────────────────────────────────────────

test "catalog: every rule id is unique" {
    for (all, 0..) |a, i| {
        for (all[i + 1 ..]) |b| {
            try std.testing.expect(!std.mem.eql(u8, a.id, b.id));
        }
    }
}

test "catalog: every body is non-empty and starts with `# <id>`" {
    for (all) |r| {
        try std.testing.expect(r.body.len > 0);
        // Header line should match `# <id>` (markdown h1 with the
        // rule id).  Catches doc/catalog mismatches at build time.
        var header_buf: [128]u8 = undefined;
        const header = try std.fmt.bufPrint(&header_buf, "# {s}\n", .{r.id});
        try std.testing.expect(std.mem.startsWith(u8, r.body, header));
    }
}

test "catalog: lookup hits and misses" {
    try std.testing.expect(lookup("heap-use-after-free") != null);
    try std.testing.expect(lookup("not-a-real-rule") == null);
}
