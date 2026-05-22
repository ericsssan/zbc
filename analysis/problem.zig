//! Re-export of shared Problem types for rule modules.
//!
//! Rules `@import("../analysis/problem.zig")` instead of
//! `@import("../problem.zig")` so that the SDK acts as a single
//! cohesive surface — the rule never needs to reach outside
//! `analysis/` for its core dependencies.

const root_problem = @import("../problem.zig");

pub const Problem = root_problem.Problem;
pub const Note = root_problem.Note;
pub const Pos = root_problem.Pos;
pub const Severity = root_problem.Severity;
