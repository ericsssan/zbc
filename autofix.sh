#!/bin/bash
# Quick auto-fix script: insert `/// @returns borrowed_from(self)` above
# every line flagged by ez/require-borrowed-from in src/linter/lint_context.zig
# and src/parser/parser.zig (where the answer is unambiguously
# borrowed_from(self) — all are `pub fn X(self: *const T, ...) ...`).
#
# linter.zig / event_resolver.zig / parent_builder.zig are NOT auto-fixed
# because their fns return OWNED slices via passed allocator — those need
# `/// @returns owned` and are done by hand.
#
# Usage:  bash tools/ez-borrow-check/autofix.sh
#         then re-run `zig build borrow-check -- <files>` to verify.

set -euo pipefail
cd "$(dirname "$0")/../.."

ZIG="$(grep ZIG Makefile | head -1 | sed 's/.*= //')"
$ZIG run tools/ez-borrow-check/main.zig -- \
    src/linter/lint_context.zig \
    src/parser/parser.zig \
    2> /tmp/borrowed_from_fix.txt || true

# Filter to only the borrowed-from rule, dedup by file:line, sort desc by
# line so insertions don't shift later lines.
grep "\[ez/require-borrowed-from\]" /tmp/borrowed_from_fix.txt \
    | awk -F: '{printf "%s:%d\n", $1, $2}' \
    | sort -t: -k1,1 -k2,2rn \
    | while IFS=: read -r file line; do
        # Insert a doc-comment line above `line`. Preserve indent of the
        # target line.
        indent=$(sed -n "${line}p" "$file" | sed 's/[^ ].*//')
        annotation="${indent}/// @returns borrowed_from(self)"
        # Use awk for portable in-place insertion.
        awk -v line="$line" -v text="$annotation" '
            NR == line { print text }
            { print }
        ' "$file" > "$file.tmp"
        mv "$file.tmp" "$file"
        echo "annotated $file:$line"
    done
