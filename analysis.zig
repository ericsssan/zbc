//! Pattern-detector rule SDK — single import surface.
//!
//! Rules in `rules/` import this module as
//! `const sdk = @import("../analysis.zig");` and access primitives
//! via `sdk.lexer.matchBrace(...)`, `sdk.scope.findIdentUseInEnclosingScope(...)`,
//! `sdk.receiver.isAllocatorishName(...)`, etc.
//!
//! Or, for rules that just need the basics, the most-used names
//! are re-exported at the top level here so rules can write
//! `sdk.matchBrace(...)` directly.

const std = @import("std");

pub const lexer = @import("analysis/lexer.zig");
pub const scope = @import("analysis/scope.zig");
pub const receiver = @import("analysis/receiver.zig");
pub const problem = @import("analysis/problem.zig");

// ── Top-level re-exports of the most-used names ─────────

// Token-walk primitives.
pub const TokenIndex = lexer.TokenIndex;
pub const TokenTag = lexer.TokenTag;
pub const matchBrace = lexer.matchBrace;
pub const matchParen = lexer.matchParen;
pub const matchBracket = lexer.matchBracket;
pub const findStmtSemicolon = lexer.findStmtSemicolon;
pub const skipDeferStmt = lexer.skipDeferStmt;
pub const skipNestedFn = lexer.skipNestedFn;
pub const skipNestedFnProtoAndBody = lexer.skipNestedFnProtoAndBody;
pub const hasTokenInRange = lexer.hasTokenInRange;
pub const returnsType = lexer.returnsType;
pub const fnProto = lexer.fnProto;
pub const bodyOf = lexer.bodyOf;
pub const iterFnDecls = lexer.iterFnDecls;
pub const FnDeclIter = lexer.FnDeclIter;

// Scope-aware iteration.
pub const findIdentUseInEnclosingScope = scope.findIdentUseInEnclosingScope;
pub const findReceiverCallSameDepth = scope.findReceiverCallSameDepth;
pub const BodyWalk = scope.BodyWalk;

// Problem types.
pub const Problem = problem.Problem;
pub const Note = problem.Note;
pub const Pos = problem.Pos;
pub const Severity = problem.Severity;

// Refute test that the SDK compiles.
test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(lexer);
    std.testing.refAllDecls(scope);
    std.testing.refAllDecls(receiver);
}
