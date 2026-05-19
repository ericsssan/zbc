# Extracting zbc to its own repo

The code in this directory is set up to live in its own repo at
some point.  This document captures the mechanical steps once
you're ready.

## Why extract

- Independent versioning + tagging.
- Outside contributors can submit PRs without cloning the whole ez
  monorepo.
- `build.zig.zon` dependency consumers (ez itself + any third party)
  pin a specific commit hash via `.url + .hash` instead of a
  brittle path.

## Pre-extraction checks

The ez build is already wired to consume zbc as a `b.dependency()`
call.  Today the dependency is `.path = "zbc"` (in-tree); after
extraction we flip to `.url + .hash`.  No other ez code change is
needed — `build.zig` already does `b.dependency("zbc", ...)`.
Verify:

```sh
cd <ez root>
grep -n "zbc" build.zig.zon  # → .zbc = .{ .path = "zbc" }
grep -n "b.dependency" build.zig  # → b.dependency("zbc", ...)
```

## Step 1 — Extract a clean repo with history preserved

Use `git filter-repo` (more reliable than `git subtree split`) to
extract just the zbc/ subtree, preserving the per-file commit
history:

```sh
cd /tmp
git clone --no-local /path/to/ez ez-extract
cd ez-extract
git filter-repo --subdirectory-filter zbc
# Now /tmp/ez-extract contains ONLY zbc's files, with history
# rewritten so commits look like they always lived at the root.
```

Verify:
- `ls` shows `build.zig`, `lib.zig`, `cfg.zig`, etc. at the root.
- `git log --oneline` shows the per-file zbc commits.
- Earlier commits that touched files outside zbc/ are dropped.

## Step 2 — Push to a new GitHub repo

Create an empty repo on GitHub (e.g. `your-org/zbc`), then:

```sh
cd /tmp/ez-extract
git remote add origin git@github.com:your-org/zbc.git
git push -u origin main
git tag v0.1.0
git push origin v0.1.0
```

## Step 3 — Update ez's dependency to url+hash

Get the dependency hash:

```sh
zig fetch --save=zbc https://github.com/your-org/zbc/archive/refs/tags/v0.1.0.tar.gz
```

That command rewrites the `.zbc = .{ .path = "zbc" }` entry in
ez's `build.zig.zon` to a url+hash form like:

```zig
.dependencies = .{
    .zbc = .{
        .url = "https://github.com/your-org/zbc/archive/refs/tags/v0.1.0.tar.gz",
        .hash = "1220...",
    },
},
```

## Step 4 — Delete the in-tree zbc/

```sh
cd <ez root>
git rm -r zbc
git commit -m "chore: drop in-tree zbc — now a build.zig.zon dependency"
```

## Step 5 — Verify

```sh
zig build test-borrow-check  # downloads + caches zbc; runs its tests
make borrow-check            # uses zbc.exe via b.dependency().artifact()
make test                    # full ez test suite
```

All three should pass identically to before the extraction.

## Rolling back

If anything breaks, the path-dependency form still works:

```sh
git revert <extraction-commit>
# Or manually:
git restore --source=<pre-extraction-sha> zbc
```

Then put back `.zbc = .{ .path = "zbc" }` in build.zig.zon.

## Pinning to a branch instead of a tag

For development against an unreleased zbc:

```zig
.zbc = .{
    .url = "git+https://github.com/your-org/zbc#main",
    .hash = "1220...",  // zig fetch will fill this in
},
```

`zig fetch --save=zbc git+https://github.com/your-org/zbc#main`
will populate the hash from the current main HEAD.

## Notes on Makefile

The ez `Makefile` directly runs `zig test zbc/main.zig` and
`zig run zbc/main.zig` for `test-borrow-check` / `borrow-check`
targets.  Those paths are independent of build.zig.zon — after
extraction they'd point at `zig-cache/p/<hash>/main.zig` instead.
For simplicity, switch the Makefile targets to invoke
`zig build test-borrow-check` and `zig build borrow-check` (which
already work via the dependency) once extraction lands.
