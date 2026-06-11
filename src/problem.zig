//! Shared output type for Layer 1 (annotation-hygiene) lint rules.
//!
//! Mirrors zlinter's `LintProblem` shape so we can swap to the zlinter
//! framework later without rewriting rules. For now we self-host —
//! zlinter requires Zig 0.16.0 release / 0.17.0-dev (pulls ZLS), and
//! we're on 0.16.0-dev.3028.

const std = @import("std");

pub const Severity = enum { off, warning, @"error" };

/// Three-valued confirmation status (issue #18 — a truth oracle for
/// findings).  Static analysis always emits `.unknown`: the rule fired,
/// but nothing has proven the finding true or false.  A downstream
/// confirmation oracle (e.g. the fuzz-harness runner) may upgrade it to:
///   - `.confirmed` — a real bug, reproduced dynamically; `witness`
///     holds the input that triggers it.
///   - `.refuted`   — proven impossible by a SOUND static argument.
///
/// Asymmetry that matters: a fuzzer that fails to crash does NOT justify
/// `.refuted` — absence of a witness is not a proof of safety, so an
/// unconfirmed finding stays `.unknown`, never auto-`.refuted`.
pub const Verdict = enum { unknown, confirmed, refuted };

pub const Pos = struct {
    /// 1-indexed line number.
    line: u32,
    /// 1-indexed column.
    column: u32,
    /// Byte offset into the source file.
    byte: u32,

    pub fn fromTokenStart(tree: *const std.zig.Ast, tok: std.zig.Ast.TokenIndex) Pos {
        const loc = tree.tokenLocation(0, tok);
        return .{
            .line = @intCast(loc.line + 1),
            .column = @intCast(loc.column + 1),
            .byte = @intCast(tree.tokens.items(.start)[tok]),
        };
    }

    pub fn fromTokenEnd(tree: *const std.zig.Ast, tok: std.zig.Ast.TokenIndex) Pos {
        const start = tree.tokens.items(.start)[tok];
        const slice = tree.tokenSlice(tok);
        const end_byte: u32 = @intCast(start + slice.len);
        const loc = tree.tokenLocation(0, tok);
        return .{
            .line = @intCast(loc.line + 1),
            .column = @intCast(loc.column + 1 + slice.len),
            .byte = end_byte,
        };
    }
};

/// Secondary diagnostic span — a related event (e.g. "value freed
/// here") that the primary report should point at.  Rendered below
/// the primary span in rich format.  Label text is owned.
pub const Note = struct {
    start: Pos,
    end: Pos,
    label: []const u8,
};

pub const Problem = struct {
    rule_id: []const u8,
    severity: Severity,
    start: Pos,
    end: Pos,
    /// Owned by the problem (caller dupes before append).
    message: []const u8,
    /// Optional secondary spans.  Owned (each `label`) plus the slice
    /// itself.  Empty slice == no notes; `&.{}` is fine.
    notes: []Note = &.{},
    /// Confirmation status (issue #18).  Defaults to `.unknown`; only a
    /// confirmation oracle sets `.confirmed` / `.refuted`.  See Verdict.
    verdict: Verdict = .unknown,
    /// Reproducing input that confirmed this finding, set together with
    /// `verdict == .confirmed`.  Owned (caller dupes).  Null otherwise.
    witness: ?[]const u8 = null,

    pub fn deinit(self: *Problem, gpa: std.mem.Allocator) void {
        gpa.free(self.message);
        for (self.notes) |n| gpa.free(n.label);
        if (self.notes.len > 0) gpa.free(self.notes);
        if (self.witness) |w| gpa.free(w);
    }
};
