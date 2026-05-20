# require-borrowed-from

A public function that returns a borrowed-shape type (`[]const u8`,
`[]const T`, `*const T`, `*T`) from a borrowed-source parameter
(`*const Ast`, `*Ast`, `*const LintContext`, …) must carry a
`/// @returns borrowed_from(<param>)` doc comment naming which
parameter's storage the return value borrows from.

Without that annotation, the escape analyzer cannot model the
return value's lifetime origin — UAK / escape on the borrowed
storage becomes silently undetectable from this function's
callers.

This rule is part of `--hygiene` mode (Layer 1).  The default
mode (escape analysis, Layer 2) does not run it.

## Example

Incorrect — `text` returns a slice borrowed from `arena`, but
zbc can't tell without the annotation:

    pub fn text(arena: *const Arena) []const u8 {
        return arena.buf.items;
    }

Fix:

    /// @returns borrowed_from(arena)
    pub fn text(arena: *const Arena) []const u8 {
        return arena.buf.items;
    }

The rule also flags annotations that name a parameter that doesn't
exist, or a parameter that isn't a borrowed-source type — catching
typos before they silently disable analysis.

## When this might be a false positive

- The returned value is actually OWNED (e.g. heap-duped from the
  parameter rather than borrowed).  In that case the annotation
  shouldn't say `borrowed_from`; add `@returns owned` instead.
- The function's "borrowed-source" parameter isn't actually a
  borrow source in your domain (the type appears in
  `Config.borrowed_source_types` but you don't want the rule to
  fire on it).  Remove the type from the list, or split the type.

## Related

- (No sibling Layer-1 rules yet.)  This rule sits alongside the
  escape-analysis rules (`heap-use-after-free` etc.); together
  Layer 1 + Layer 2 form a "annotations present + invariants
  respected" pair.
