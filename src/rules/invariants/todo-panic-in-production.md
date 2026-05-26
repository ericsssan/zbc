# todo-panic-in-production

`@panic("TODO ...")` / `@panic("unimplemented")` / `@panic("FIXME ...")`
left in code that runs in release builds.  TODO-panics are a development
scaffold: harmless during prototyping but they crash users when the
branch is reached in production.

## Example

Incorrect:

    fn handleEvent(event: Event) void {
        switch (event) {
            .click => process(event),
            .drag  => @panic("TODO: implement drag"),   // ← crashes users
        }
    }

Fix — return an explicit error if the fn can propagate one:

    fn handleEvent(event: Event) !void {
        switch (event) {
            .click => process(event),
            .drag  => return error.NotYetImplemented,
        }
    }

Or gate unreachable branches at compile time:

    fn handleEvent(comptime event: EventKind) void { ... }

## What is flagged

`@panic` calls whose string literal argument contains any of:
`TODO`, `FIXME`, `XXX`, `HACK`, `WIP`, `unimplemented`,
`not implemented`, `not yet`, `stub` (case-insensitive prefix/substring
match).

`unreachable` is NOT flagged — it is the canonical Zig marker for
branches proven unreachable by construction.

## When this might be a false positive

- A panic message that happens to contain these words for a non-TODO
  reason (e.g. `@panic("previous allocator freed without zeroing")`).
  The match is conservative enough that this is rare.
- Test helpers that intentionally panic with a TODO message in debug
  builds only — those should use `if (builtin.mode == .Debug) @panic(...)`.
