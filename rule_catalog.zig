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
