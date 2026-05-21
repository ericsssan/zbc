//! Layer 2 CFG types and Zig-AST → CFG lowering.
//!
//! v1 scope: extract a flow graph from a single Zig function over the
//! subset of statement shapes that affect our abstract state.  Most
//! Zig syntax doesn't change lifetime/identity; we collapse it into
//! `.plain_expr` and only emit dedicated statement nodes for the ops
//! the analyzer transfers over.
//!
//! What we DO model:
//!   - `var/const NAME = INIT;` (local binding)
//!   - `LHS = RHS;` (assignment)
//!   - call expressions (especially annotated-callee returns)
//!   - `arena.deinit()` (arena death)
//!   - `thread.join()` (thread join)
//!   - `return EXPR;` (function exit)
//!   - `if/else`, `while`, `for`, `switch` branching (real CFG edges)
//!   - `defer` / `errdefer` (replayed at function-exit / return sites)
//!
//! What we DON'T model (yet):
//!   - `try` / `catch` (error-path forking + error-set tracking)
//!   - generics / comptime
//!   - for-loop iteration variable origin (treated as .plain)
//!   - switch-case pattern bindings (treated as .plain)
//!
//! Errors during lowering are surfaced as `Stmt{.lowering_gap}` nodes
//! rather than aborts — keeps the analyzer running on the rest of the
//! function even when one statement uses an unsupported construct.

const std = @import("std");
const Ast = std.zig.Ast;
const abstract_state = @import("abstract_state.zig");
const annotations = @import("annotations.zig");
const imports = @import("imports.zig");
const remote_resolver = @import("remote_resolver.zig");
const config_mod = @import("config.zig");

pub const Config = config_mod.Config;

/// Cross-file resolution context passed into lowerFunction.  When
/// present, classifyCall resolves `imported.method(...)` callees by
/// looking up the method's annotation in the imported file's DB.
pub const RemoteCtx = struct {
    imap: *const imports.Map,
    base_dir: []const u8,
    cache: *remote_resolver.Cache,
};

pub const BlockId = abstract_state.BlockId;
pub const LocalId = abstract_state.LocalId;

// ── Source position ─────────────────────────────────────────

pub const SrcPos = struct {
    /// Byte offset into source.
    byte: u32,
    /// 1-indexed line.
    line: u32,
    /// 1-indexed column.
    column: u32,
};

// ── Statements ─────────────────────────────────────────────

pub const StmtKind = union(enum) {
    /// `var/const NAME = INIT;` — local declared, bound to RHS.
    decl: struct { local: LocalId, init_kind: ExprKind },

    /// `LHS = RHS;` — overwrite local with new RHS.
    assign: struct { target: LocalId, rhs_kind: ExprKind },

    /// `<receiver>.deinit()` on an arena.  Marks the arena dead.
    arena_kill: struct { arena_local: LocalId },

    /// `gpa.free(p)` / `gpa.destroy(p)` — marks the heap allocation
    /// bound to `freed_local` dead.  Double-free fires here.
    heap_free: struct {
        freed_local: LocalId,
        /// Fallback HeapId — used by transferHeapFree when the local
        /// has no prior tracked .heap origin (e.g. inter-procedural
        /// free of a `*T` parameter via @takes ownership(0); the
        /// caller might have allocated, or might not have, but we
        /// know the callee took ownership so any subsequent use is
        /// undefined regardless).  Same shape as
        /// .field_heap_free.fallback_hid.
        fallback_hid: abstract_state.HeapId,
    },

    /// `obj.field = RHS;` — write to a struct field.  We track field
    /// origins separately from the parent local so heap allocations
    /// stored in fields can be freed and UAF-checked.
    field_assign: struct { parent: LocalId, name: []const u8, rhs_kind: ExprKind },

    /// `g.free(obj.field)` / `g.destroy(obj.field)` — kill a field's
    /// heap allocation.
    field_heap_free: struct {
        parent: LocalId,
        name: []const u8,
        /// Synthetic HeapId minted at cfg-build time, used by
        /// transferFieldHeapFree when the field has no prior tracked
        /// origin (e.g. an inter-procedural free of a field on a
        /// `*T` parameter where the allocation happened in the
        /// caller).  Lets subsequent .field_use reads see a .dead
        /// state and fire UAF.  Without this, only fields with an
        /// in-function alloc + free pair were trackable.
        fallback_hid: abstract_state.HeapId,
    },

    /// Read of `obj.field` — fires UAF / use-of-undef checks against
    /// the field's tracked origin (separate from the parent local's).
    field_use: struct { parent: LocalId, name: []const u8 },

    /// Synthetic check emitted before a `.ret` when the return-value
    /// expression contains MORE than one borrow of a local
    /// (composite literal embedding multiple `&local` / array-slice
    /// references).  The primary value_kind on `.ret` fires for the
    /// first; one `.composite_escape` per additional one catches
    /// the rest.  Fires escape checks against `local`'s current
    /// origin regardless of return type — same model as transferRet
    /// for composite-borrow value-shape returns.
    composite_escape: struct { local: LocalId },

    /// `return <expr>;` — function exit.  `value_kind` describes what's
    /// being returned.  `is_borrowed_return_type` tags whether the
    /// enclosing function's signature returns a borrowed-shape type
    /// (slice/pointer) — only those returns can leak a borrowed
    /// origin.  Value-typed returns MOVE the value (and any arena it
    /// owns) to the caller and are exempt from the escape check.
    ret: struct {
        value_kind: ExprKind,
        is_borrowed_return_type: bool,
        /// `return undefined;` written literally — canonical sentinel
        /// for comptime-gated branches (e.g. `if (comptime X) return
        /// undefined;` in bindgen stubs).  The author is explicitly
        /// opting in to returning garbage on a path the caller is
        /// comptime-guaranteed not to use.  The real undef-leak bug
        /// class is `var x: T = undefined; return x;` (via identifier),
        /// which still flows through .undef and gets caught.
        is_literal_undef: bool = false,
    },

    /// Use of a local (to read it).  Generates "is origin still live?"
    /// checks in the analyzer.
    /// Write through a pointer / field of `target` (e.g.
    /// `arena.* = X;`, `obj.field = X;`).  Does NOT rebind the
    /// local — its resource identity (.heap / .arena) is unchanged.
    /// Only clears .undef → .plain (the underlying storage was
    /// initialized via this write).
    pointer_write: struct { target: LocalId },
    /// Write through a `*T` parameter (or pointer-typed local) to
    /// caller-visible storage — `out.* = X;` or `out.field = X;`
    /// where `out` is pointer-typed.  Mirrors the escape-style
    /// checks at `return`: a value whose lifetime ends with this
    /// function (function-local arena, stack reference) being
    /// reachable from caller-owned storage is an escape.  `out`
    /// is the pointer-typed local; `value_kind` is the RHS
    /// classification used to derive the written value's origin.
    out_param_write: struct { out: LocalId, value_kind: ExprKind },
    /// Re-bind a local to .plain.  Emitted at loop body entry for
    /// `while (it) |n|` / `for (xs) |x|` captures so back-edges
    /// don't carry one iteration's `free(n)` state into the next —
    /// the capture refers to a different element each iteration.
    /// Without this, the @takes-ownership / heap_free fallback path
    /// (which now marks plain locals as .heap.dead) cascades
    /// spurious double-free reports across loop iterations.
    reset_capture: struct { local: LocalId },
    use: struct {
        local: LocalId,
        /// True when this .use was emitted by a method-call walker
        /// pass (`x.method(...)`).  Method-call receivers on a local
        /// whose current origin is .undef are almost certainly init
        /// calls (you don't read garbage); transferUse clears .undef
        /// to .plain instead of firing use_undefined.  For .heap /
        /// .arena origins, the call still counts as a real use.
        from_method_call: bool = false,
    },

    /// Statement shape we couldn't lower precisely.  Conservative:
    /// analyzer collapses every local's origin to .plain.
    lowering_gap: struct { note: []const u8 },
};

pub const Stmt = struct {
    kind: StmtKind,
    /// Start position — first token of the source construct.
    pos: SrcPos,
    /// End position (exclusive) — one past the last token.  Used to
    /// emit span-based Problem diagnostics (editors highlight the
    /// full construct, not just a single column).  When the
    /// statement isn't derived from a real source node (synthetic
    /// gaps, etc.), the emitter may set end_pos == pos as a sentinel
    /// and the diagnostic falls back to a single-column range.
    end_pos: SrcPos,
};

// ── Expression-result classification ────────────────────────

/// Shape of a value produced by an expression.  We don't model expressions
/// as trees; just classify what the RHS produces lifetime-wise.
pub const ExprKind = union(enum) {
    /// Literal, arithmetic, value-typed call — no lifetime constraint.
    plain,
    /// Call to a fn annotated `// @returns borrowed_from(<param>)`.
    /// `borrowed_from_local` is the local that the lifetime is tied to.
    borrowed_from: LocalId,
    /// Call to a fn annotated `// @returns owned` — caller owns, no
    /// lifetime constraint despite borrowed-shape signature.
    owned,
    /// `ArenaAllocator.init(...)` — produces a fresh arena.  The
    /// ArenaId is minted at lowering time so worklist re-visits of
    /// the same call site reuse the SAME id; otherwise loops would
    /// blow `state.arenas` up unboundedly.
    /// Fresh arena.  `is_heap_allocated` distinguishes stack-
    /// allocated (`var a = ArenaAllocator.init(...)`) from heap-
    /// allocated (`var a = gpa.create(ArenaAllocator)`) — both
    /// mint an ArenaId for UAK tracking, but out-param escape
    /// gates on this.
    arena_init: struct { id: abstract_state.ArenaId, is_heap_allocated: bool = false },
    /// Heap allocation call (gpa.alloc / gpa.create / dupe / ...).
    /// HeapId is minted at lowering time, same reasoning as arena_init.
    heap_alloc: abstract_state.HeapId,
    /// `&<local>` — address-of a function-local.  Produces a pointer
    /// whose lifetime is bound to that local's stack frame.
    stack_ref: LocalId,
    /// A composite/aggregate expression (struct literal, array
    /// literal, etc.) whose return-shape borrows from `local`.
    /// Distinct from `.copy_of` so transferRet can fire escape
    /// checks regardless of return type — the surrounding composite
    /// makes this a borrow embedded in a value, not a move of the
    /// resource itself.
    composite_borrow: LocalId,
    /// `undefined` keyword — the value is explicitly uninitialized.
    undef,
    /// Reading a local — pass-through of that local's current origin.
    copy_of: LocalId,
    /// Reading `parent.name` — pass-through of the field's current
    /// origin (looked up in state.fields).
    field_copy_of: struct { parent: LocalId, name: []const u8 },
    /// Couldn't classify — conservative .plain at use site.
    unknown,
};

// ── Basic block ────────────────────────────────────────────

pub const BasicBlock = struct {
    id: BlockId,
    stmts: []Stmt,
    /// Successor blocks in CFG.  Empty for terminal blocks (after return).
    /// Two successors for branches (if/while); the analyzer joins their
    /// post-states at the merge block.
    successors: []BlockId,
};

// ── CFG ────────────────────────────────────────────────────

pub const Cfg = struct {
    blocks: []BasicBlock,
    entry: BlockId,
    /// Source span of the function whose body this CFG represents.
    fn_span: struct { start: u32, end: u32 },
    /// Local-name table (name & decl position keyed by LocalId).
    locals: []LocalInfo,
    /// Path strings referenced by `field_assign` / `field_use`
    /// statements that aren't contiguous in source — e.g. struct-
    /// literal unpacking builds "parent_prefix.field_name" from two
    /// disjoint tokens.  Most paths ARE source slices (no entry
    /// here); these own the rest.
    owned_paths: [][]u8 = &.{},

    pub fn deinit(self: *Cfg, gpa: std.mem.Allocator) void {
        for (self.blocks) |b| {
            gpa.free(b.stmts);
            gpa.free(b.successors);
        }
        gpa.free(self.blocks);
        gpa.free(self.locals);
        for (self.owned_paths) |p| gpa.free(p);
        gpa.free(self.owned_paths);
    }
};

pub const LocalInfo = struct {
    name: []const u8, // borrowed from source — caller keeps source alive
    decl_pos: SrcPos,
    /// True iff the local was declared with an array type annotation
    /// like `var x: [N]T = ...`.  Set so slice-of-local classification
    /// only flags real stack arrays — slicing a local that holds a
    /// slice or pointer just produces another view of caller-owned
    /// storage, not an escape.
    is_array: bool = false,
    /// True iff the local's declared type begins with `*` (possibly
    /// preceded by `?` or `const`) — i.e. the local is a pointer
    /// (typically a `*Self` parameter).  The pointee lives in the
    /// caller, so `&local.field` for a pointer-typed local is NOT a
    /// stack-frame borrow; it's a borrow from caller-owned storage.
    /// Address-of classification gates on this to avoid spurious
    /// stack-escape on the common `return &self.field` shape.
    is_pointer: bool = false,
    /// Coarse classification of the init expression — lets the
    /// composite-borrow walker decide at classify time whether a
    /// bare reference to this local in a returned struct should be
    /// treated as a borrow source.  Set at registerLocalFull from
    /// the same classifier that produces the .decl's init_kind.
    init_hint: InitHint = .other,
    /// If this local was declared from a bare identifier that names
    /// a fn in our annotation DB, the name of that fn.  Lets call
    /// sites `local(args)` resolve through the binding to the
    /// underlying fn's annotation.
    bound_fn_name: ?[]const u8 = null,
    /// The local's declared base type name (e.g. "Foo" for `*Foo`,
    /// `*const Foo`, `?*Foo`), with pointer/optional/const wrappers
    /// stripped.  `*Self` / `*@This()` is resolved to the enclosing
    /// fn's containing type.  Null when the local has no explicit
    /// type annotation (inferred type — not tracked).
    ///
    /// Used by call-site lookup to disambiguate `<recv>.method()`
    /// across method-name overloads on different types.
    type_name: ?[]const u8 = null,
};

pub const InitHint = enum {
    other,
    /// Local was initialized from `ArenaAllocator.init(...)` — IS the arena.
    arena_local,
    /// Local was initialized from `<arena_local>.allocator()` (directly
    /// or via copy of another arena_allocator local).  Tracks "this
    /// std.mem.Allocator value's storage dies with arena X" so calls
    /// to `.alloc()` / `.create()` / etc. through this allocator
    /// produce arena-bound memory (.arena origin), not a fresh .heap
    /// allocation.  Without this, arena-UAK on the standard pattern
    /// `const a = arena.allocator(); buf = a.alloc(...); arena.deinit(); use(buf);`
    /// would never fire — buf would carry a heap id unrelated to arena.
    arena_allocator,
    heap_local,
    noreturn_alias,
};

/// Known-stdlib noreturn callee chains.  Hoisted so both the
/// call-site detector (calleeIsNoreturn) and the alias detector
/// (initIsNoreturnAlias) share a single list.  Builtins like
/// `@panic` and `@trap` go through builtinIsDivergent, not here.
const known_noreturn_chains = [_][]const u8{
    "process.exit",
    "posix.exit",
    "os.abort",
    "process.abort",
};

// ── Lowering ───────────────────────────────────────────────

/// Lower a single Zig function body (block_two or block_two_semicolon
/// for short, block / block_semicolon for longer) into a CFG.  Returns
/// null when the function has no body (extern, etc.).
pub fn lowerFunction(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    fn_decl: Ast.Node.Index,
    db: ?*const annotations.Db,
) !?Cfg {
    return lowerFunctionFull(gpa, tree, fn_decl, db, null, &config_mod.Default);
}

/// Backwards-compat alias from phase 22.  Forwards to lowerFunctionFull
/// with the Default config — preserves the previous 5-arg signature.
pub fn lowerFunctionWithRemote(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    fn_decl: Ast.Node.Index,
    db: ?*const annotations.Db,
    remote: ?*const RemoteCtx,
) !?Cfg {
    return lowerFunctionFull(gpa, tree, fn_decl, db, remote, &config_mod.Default);
}

/// Main entry point.  Generalizes the per-project knobs into Config
/// (phase 42).  Existing callers that don't pass a Config get
/// `Default`, which matches the historical ez behavior — type name
/// "Ast", text patterns "Ast.parse" / "ArenaAllocator.init" /
/// ".deinit(" / ".join(".
pub fn lowerFunctionFull(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    fn_decl: Ast.Node.Index,
    db: ?*const annotations.Db,
    remote: ?*const RemoteCtx,
    config: *const Config,
) !?Cfg {
    var buf: [1]Ast.Node.Index = undefined;
    const fn_proto = (try fnProto(tree, &buf, fn_decl)) orelse return null;
    const body_node = bodyOf(tree, fn_decl) orelse return null;

    // Pre-classify the fn's return type.  Only borrowed-shape returns
    // (slice/pointer) can leak a borrowed origin to the caller; value
    // returns move the value and are exempt from the escape check.
    const is_borrowed_ret = if (fn_proto.ast.return_type.unwrap()) |rt|
        returnTypeIsBorrowed(tree, rt)
    else
        false;

    // Check whether THIS fn carries `@returns owns_locals` — if so,
    // suppress composite-borrow detection inside its body.
    const suppress_cb = blk: {
        const d = db orelse break :blk false;
        const name_tok = fn_proto.name_token orelse break :blk false;
        const name = tree.tokenSlice(name_tok);
        const entry = d.lookup(name) orelse break :blk false;
        const a = entry.annotation orelse break :blk false;
        break :blk a == .owns_locals;
    };

    // Pull the containing type for this fn_decl from the DB's
    // pre-pass map so Self / @This() resolve inside param types and
    // receiver-type lookups have a starting scope.
    const self_type: ?[]const u8 = if (db) |d| d.containingType(fn_decl) else null;

    var builder: Builder = .{
        .gpa = gpa,
        .tree = tree,
        .db = db,
        .remote = remote,
        .config = config,
        .is_borrowed_return_type = is_borrowed_ret,
        .suppress_composite_borrow = suppress_cb,
        .fn_proto = fn_proto,
        .self_type = self_type,
    };
    defer builder.tempDeinit();

    const entry_id = try builder.newBlock();
    var cur_block = entry_id;
    try builder.lowerFunctionBody(body_node, &cur_block);

    return try builder.finalize(tree, fn_decl, entry_id);
}

fn fnProto(tree: *const Ast, buf: *[1]Ast.Node.Index, node: Ast.Node.Index) !?Ast.full.FnProto {
    return switch (tree.nodeTag(node)) {
        .fn_decl => switch (tree.nodeTag(tree.nodeData(node).node_and_node[0])) {
            .fn_proto => tree.fnProto(tree.nodeData(node).node_and_node[0]),
            .fn_proto_multi => tree.fnProtoMulti(tree.nodeData(node).node_and_node[0]),
            .fn_proto_one => tree.fnProtoOne(buf, tree.nodeData(node).node_and_node[0]),
            .fn_proto_simple => tree.fnProtoSimple(buf, tree.nodeData(node).node_and_node[0]),
            else => null,
        },
        else => null,
    };
}

/// Does `text` contain any of `patterns` as a substring?  Used by
/// the classifier + lowerCallStmt to dispatch on
/// project-configurable text matches (phase 42).
fn anyPatternMatches(text: []const u8, patterns: []const []const u8) bool {
    for (patterns) |p| {
        if (std.mem.indexOf(u8, text, p) != null) return true;
    }
    return false;
}

/// Heuristic: does the type expression's text contain a standalone
/// `config.ast_type_name` identifier token?  Matches `<Name>`, `*<Name>`,
/// `*const <Name>`, `?<Name>`, `[]const <Name>`, etc.  Identifier-token
/// boundary check, so e.g. `FooAst` wouldn't match a Name="Ast" config
/// but `Ast.Node` would.  False positives are bounded — extra params
/// tagged as Origin.ast inflate the AstId counter but don't cause
/// false-positive invariant findings.
/// True if the param's type mentions the ast_type_name OR any
/// configured ast_holder_types.  Same logic as annotations.zig's
/// inference, duplicated to keep cfg free of annotation dependencies.
/// Used by seedParams to give holder-typed params Origin.ast so the
/// flow-side checks fire on call sites inside fns that receive a
/// wrapped Ast (e.g. *const LintContext).
fn paramTypeCarriesAst(tree: *const Ast, type_node: Ast.Node.Index, config: *const Config) bool {
    if (typeMentionsAst(tree, type_node, config.ast_type_name)) return true;
    for (config.ast_holder_types) |holder| {
        if (typeMentionsAst(tree, type_node, holder)) return true;
    }
    return false;
}

fn typeMentionsAst(tree: *const Ast, type_node: Ast.Node.Index, name: []const u8) bool {
    const first = tree.firstToken(type_node);
    const last = tree.lastToken(type_node);
    var t: Ast.TokenIndex = first;
    while (t <= last) : (t += 1) {
        if (tree.tokens.items(.tag)[t] == .identifier and
            std.mem.eql(u8, tree.tokenSlice(t), name))
            return true;
    }
    return false;
}

fn bodyOf(tree: *const Ast, node: Ast.Node.Index) ?Ast.Node.Index {
    if (tree.nodeTag(node) != .fn_decl) return null;
    return tree.nodeData(node).node_and_node[1];
}

// ── Builder ────────────────────────────────────────────────

const LoopCtx = struct {
    header: BlockId,
    merge: BlockId,
    /// Label slice on the source (no colon), or null for unlabeled
    /// loops.  `break :name` walks the loop stack from inside out
    /// matching this field.
    label: ?[]const u8 = null,
};

/// Labeled non-loop blocks — `blk: { ... break :blk val; }`.  Only
/// labeled break can target these; continue is invalid (compiler
/// catches at parse time, but defensively ignored here).
const BlockLabelCtx = struct {
    label: []const u8,
    merge: BlockId,
};

const DeferKind = enum { normal, err };
const DeferEntry = struct { kind: DeferKind, body: Ast.Node.Index };

const Builder = struct {
    gpa: std.mem.Allocator,
    tree: *const Ast,
    db: ?*const annotations.Db = null,
    remote: ?*const RemoteCtx = null,
    config: *const Config = &config_mod.Default,
    /// The struct/union/enum that contains the fn being lowered.  Set
    /// by the caller of `build` per fn (via `lib.zig`'s walker).
    /// Used to resolve `Self` / `*@This()` in param types and to seed
    /// the lookup namespace for `<recv>.method()` disambiguation.
    self_type: ?[]const u8 = null,
    blocks: std.ArrayListUnmanaged(BasicBlock) = .empty,
    /// Per-block staging — stmts being appended.  Flushed to `blocks[i].stmts`
    /// in finalize().
    block_stmts: std.ArrayListUnmanaged(std.ArrayListUnmanaged(Stmt)) = .empty,
    block_successors: std.ArrayListUnmanaged(std.ArrayListUnmanaged(BlockId)) = .empty,
    locals: std.ArrayListUnmanaged(LocalInfo) = .empty,
    /// Parsed fn prototype for the fn being lowered.  Used by
    /// registerFnParams.  Optional only for cfg-builder constructs
    /// outside of normal fn lowering (currently none).
    fn_proto: ?Ast.full.FnProto = null,
    /// name → LocalId for current scope.  v1 doesn't handle nested scopes;
    /// names are flat per-function.
    name_to_local: std.StringHashMapUnmanaged(LocalId) = .empty,
    /// Unified declaration-ordered stack of `defer` / `errdefer`
    /// bodies, LIFO.  Replayed at every `return` (normal only) and
    /// at synthetic err-exit sinks (both kinds, interleaved by
    /// declaration order so that Zig's semantics — defers + errdefers
    /// fire in reverse declaration order — are preserved).
    ///
    /// Previously two separate lists (normal/err) caused err-exit
    /// flushing to fire ALL errdefers before ANY defers, which is
    /// wrong: an `errdefer free(p);` followed by a `defer use(p);`
    /// declared later would, on error, run free→use → spurious UAF
    /// inside the synthetic err_exit block.  Single list with kind
    /// tag preserves order.
    deferred: std.ArrayListUnmanaged(DeferEntry) = .empty,
    /// Loop context stack — pushed by lowerWhile/lowerFor before
    /// lowering the body, popped after.  `break` jumps to the
    /// innermost merge; `continue` jumps to the innermost header.
    /// Labels aren't modeled yet (always targets the innermost loop).
    loop_stack: std.ArrayListUnmanaged(LoopCtx) = .empty,
    /// Labeled-block stack — pushed by lowerLabeledBlock around the
    /// body; searched before loop_stack on labeled-break resolution.
    block_label_stack: std.ArrayListUnmanaged(BlockLabelCtx) = .empty,
    /// Stack of `errdefer` bodies, LIFO.  Replayed on error-exit paths
    /// only (try/catch — phase 9+).  At a plain `return X` Zig only fires
    /// these when X is an error value, but we can't always tell from
    /// AST, so for now we conservatively SKIP errdefers at returns; this
    /// trades one false-negative class (errdefer killing an arena before
    /// an error return uses it) for elimination of the converse false-
    /// positive class (errdefer kills polluting success returns).
    /// True iff the enclosing fn returns a borrowed-shape type.
    /// Threaded into `Stmt.ret.is_borrowed_return_type`.
    is_borrowed_return_type: bool = false,
    /// Set when the enclosing fn carries `@returns owns_locals`.
    /// firstBorrowedLocal returns null when this is set, so the
    /// composite-borrow check stays silent for explicit
    /// ownership-transfer functions (the canonical init() pattern).
    suppress_composite_borrow: bool = false,
    /// Per-function counters for minting ArenaId / HeapId.  Done at
    /// lowering time so worklist re-visits of the same call site
    /// reuse the same id; otherwise loops would grow state.arenas
    /// and state.heaps unboundedly.
    next_arena: u32 = 0,
    next_heap: u32 = 0,
    /// Path strings the builder allocated (currently used for
    /// struct-literal unpacking, where `parent_prefix.field_name`
    /// is non-contiguous in source).  Transferred to Cfg at finalize
    /// and freed in Cfg.deinit.
    owned_paths: std.ArrayListUnmanaged([]u8) = .empty,

    fn tempDeinit(self: *Builder) void {
        for (self.block_stmts.items) |*s| s.deinit(self.gpa);
        self.block_stmts.deinit(self.gpa);
        for (self.block_successors.items) |*s| s.deinit(self.gpa);
        self.block_successors.deinit(self.gpa);
        self.blocks.deinit(self.gpa);
        self.locals.deinit(self.gpa);
        self.name_to_local.deinit(self.gpa);
        self.deferred.deinit(self.gpa);
        self.loop_stack.deinit(self.gpa);
        self.block_label_stack.deinit(self.gpa);
        for (self.owned_paths.items) |p| self.gpa.free(p);
        self.owned_paths.deinit(self.gpa);
    }

    fn newBlock(self: *Builder) !BlockId {
        const id: BlockId = @enumFromInt(self.blocks.items.len);
        try self.blocks.append(self.gpa, .{
            .id = id,
            .stmts = &.{},
            .successors = &.{},
        });
        try self.block_stmts.append(self.gpa, .empty);
        try self.block_successors.append(self.gpa, .empty);
        return id;
    }

    fn appendStmt(self: *Builder, block: BlockId, stmt: Stmt) !void {
        try self.block_stmts.items[@intFromEnum(block)].append(self.gpa, stmt);
    }

    fn addEdge(self: *Builder, from: BlockId, to: BlockId) !void {
        try self.block_successors.items[@intFromEnum(from)].append(self.gpa, to);
    }

    fn registerLocal(self: *Builder, name: []const u8, pos: SrcPos) !LocalId {
        return self.registerLocalWithType(name, pos, false, .other, null, null);
    }

    fn registerLocalWithPointerHint(
        self: *Builder,
        name: []const u8,
        pos: SrcPos,
        is_array: bool,
        init_hint: InitHint,
        bound_fn_name: ?[]const u8,
        type_name: ?[]const u8,
        is_pointer: bool,
    ) !LocalId {
        const id: LocalId = @enumFromInt(self.locals.items.len);
        try self.locals.append(self.gpa, .{
            .name = name,
            .decl_pos = pos,
            .is_array = is_array,
            .init_hint = init_hint,
            .bound_fn_name = bound_fn_name,
            .type_name = type_name,
            .is_pointer = is_pointer,
        });
        try self.name_to_local.put(self.gpa, name, id);
        return id;
    }

    fn registerLocalFull(
        self: *Builder,
        name: []const u8,
        pos: SrcPos,
        is_array: bool,
        init_hint: InitHint,
        bound_fn_name: ?[]const u8,
    ) !LocalId {
        return self.registerLocalWithType(name, pos, is_array, init_hint, bound_fn_name, null);
    }

    fn registerLocalWithType(
        self: *Builder,
        name: []const u8,
        pos: SrcPos,
        is_array: bool,
        init_hint: InitHint,
        bound_fn_name: ?[]const u8,
        type_name: ?[]const u8,
    ) !LocalId {
        const id: LocalId = @enumFromInt(self.locals.items.len);
        try self.locals.append(self.gpa, .{
            .name = name,
            .decl_pos = pos,
            .is_array = is_array,
            .init_hint = init_hint,
            .bound_fn_name = bound_fn_name,
            .type_name = type_name,
        });
        try self.name_to_local.put(self.gpa, name, id);
        return id;
    }

    /// True iff `type_node`'s first two tokens are `[<number>` —
    /// the shape of `[N]T`.  Conservatively returns false for
    /// `[*]T` (many-pointer), `[]T` (slice), `[*c]T` (C pointer).
    fn typeIsStackArray(self: *Builder, type_node: Ast.Node.Index) bool {
        const tree = self.tree;
        const first = tree.firstToken(type_node);
        const tags = tree.tokens.items(.tag);
        if (tags[first] != .l_bracket) return false;
        if (first + 1 >= tree.tokens.len) return false;
        return tags[first + 1] == .number_literal;
    }

    /// True iff `type_node` begins with `*` (possibly preceded by
    /// `?` or `const`) — the shape of a pointer.  Used to gate the
    /// `&local.field` → `.stack_ref(local)` extension so we don't
    /// FP on `&self.field` where `self` is a pointer parameter.
    fn typeIsPointer(self: *Builder, type_node: Ast.Node.Index) bool {
        const tree = self.tree;
        const first = tree.firstToken(type_node);
        const last = tree.lastToken(type_node);
        const tags = tree.tokens.items(.tag);
        var t: Ast.TokenIndex = first;
        while (t <= last) : (t += 1) {
            switch (tags[t]) {
                .question_mark, .keyword_const => continue,
                .asterisk => return true,
                else => return false,
            }
        }
        return false;
    }

    /// Walk the type expression's tokens, stripping pointer / optional
    /// / const wrappers, and return the BASE identifier — the LAST
    /// component of a dotted chain.  `*Foo` → "Foo"; `*const Foo` →
    /// "Foo"; `?*Foo` → "Foo"; `*lib.Foo` → "Foo" (the namespace
    /// prefix is discarded — the type identity is what matters for
    /// method dispatch).  Returns null when no plain identifier is
    /// found — e.g. slice `[]T`, function pointer, anonymous struct.
    ///
    /// `Self` / `@This()` resolves to the enclosing fn's containing
    /// type when `self_type` is supplied.
    fn extractTypeName(self: *Builder, type_node: Ast.Node.Index, self_type: ?[]const u8) ?[]const u8 {
        const tree = self.tree;
        const first = tree.firstToken(type_node);
        const last = tree.lastToken(type_node);
        const tags = tree.tokens.items(.tag);
        var t: Ast.TokenIndex = first;
        // Strip leading `?`, `*`, `const` tokens.
        while (t <= last) : (t += 1) {
            switch (tags[t]) {
                .question_mark, .asterisk, .keyword_const => continue,
                .l_bracket => return null,
                .identifier, .builtin => break,
                else => return null,
            }
        }
        if (t > last) return null;
        // Walk identifiers/builtins separated by dots; remember the
        // last identifier seen.  `lib.HTMLRewriter` → "HTMLRewriter".
        var last_name: ?[]const u8 = null;
        var expecting_ident = true;
        while (t <= last) : (t += 1) {
            const tag = tags[t];
            if (expecting_ident) {
                if (tag == .identifier) {
                    const n = tree.tokenSlice(t);
                    last_name = if (std.mem.eql(u8, n, "Self")) self_type else n;
                    expecting_ident = false;
                } else if (tag == .builtin) {
                    const n = tree.tokenSlice(t);
                    if (std.mem.eql(u8, n, "@This")) {
                        last_name = self_type;
                        expecting_ident = false;
                    } else return null;
                } else return null;
            } else {
                if (tag == .period) {
                    expecting_ident = true;
                } else break;
            }
        }
        return last_name;
    }

    /// Register `|x|` / `|x, y|` / `|*x, idx|` capture identifiers
    /// starting at `payload_token` (which points at the first capture
    /// after the opening `|`).  Stops at the closing `|`.  Each
    /// capture becomes a tracked local with .unknown origin — we don't
    /// model per-element borrow shape yet, but subsequent uses inside
    /// the body now resolve via name_to_local rather than falling
    /// through to .unknown identifier classification.
    fn registerCaptures(self: *Builder, payload_token: Ast.TokenIndex) !void {
        _ = try self.registerCapturesWith(payload_token, null);
    }

    /// Variant that, when `reset_into` is non-null, emits a
    /// .reset_capture stmt for each registered capture into the
    /// given block.  Used by loop lowerers so each iteration starts
    /// with a fresh .plain origin for the capture (back-edge state
    /// would otherwise propagate across iterations — the capture
    /// refers to a different element each time).
    fn registerCapturesWith(self: *Builder, payload_token: Ast.TokenIndex, reset_into: ?BlockId) !void {
        const tree = self.tree;
        const tags = tree.tokens.items(.tag);
        var t: Ast.TokenIndex = payload_token;
        while (t < tags.len) : (t += 1) {
            switch (tags[t]) {
                .pipe => return, // closing `|`
                .identifier => {
                    const name = tree.tokenSlice(t);
                    if (std.mem.eql(u8, name, "_")) continue;
                    const lid = try self.registerLocal(name, self.posOfToken(t));
                    if (reset_into) |blk| {
                        try self.appendStmt(blk, .{
                            .kind = .{ .reset_capture = .{ .local = lid } },
                            .pos = self.posOfToken(t),
                            .end_pos = self.posOfToken(t),
                        });
                    }
                },
                else => {}, // `,`, `*`, `|` (opening): skip
            }
        }
    }

    /// Lower the contents of a Zig block node into `cur` (mutated to the
    /// last block reached — branches may have advanced past the original).
    /// Defer statements encountered are queued and replayed in reverse
    /// order at every `return` exit point.  Does NOT flush defers at
    /// block exit — only the top-level function body does that, via
    /// `lowerFunctionBody`.
    fn lowerBlock(self: *Builder, block_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        var stmt_buf: [2]Ast.Node.Index = undefined;
        const stmts = blockStmts(tree, block_node, &stmt_buf);

        // Scope-bound defer handling.  Zig defers fire at the
        // enclosing BLOCK's exit, not just at return.  We snapshot
        // the unified defer stack here; any defer/errdefer pushed
        // inside this block is fired (LIFO) at fallthrough exit,
        // then popped so a later return doesn't re-fire it from an
        // already-exited scope.
        const save = self.deferred.items.len;

        for (stmts) |stmt_idx| {
            try self.lowerStmt(stmt_idx, cur);
        }

        // Fire defers added inside this block at fallthrough exit.
        // Errdefers do NOT fire on fallthrough (success path) — they
        // only fire on error returns, handled in flushErrAndNormalDefers.
        var i = self.deferred.items.len;
        while (i > save) {
            i -= 1;
            const entry = self.deferred.items[i];
            if (entry.kind == .normal) {
                try self.lowerStmt(entry.body, cur);
            }
        }
        self.deferred.shrinkRetainingCapacity(save);
    }

    /// Lower the top-level function body.  lowerBlock now flushes
    /// its own defers at fallthrough exit, so no separate flush is
    /// needed here.
    fn lowerFunctionBody(self: *Builder, body_node: Ast.Node.Index, cur: *BlockId) !void {
        // Register function parameters as locals so the body can
        // reference them (e.g. `b.foo` where `b` is a `*Bar` param).
        // Params get .other init_hint and .plain origin — they're
        // caller-owned; the analysis only flags state changes that
        // happen INSIDE this function.  Without registration,
        // inter-procedural patterns like `b.foo.dispose()` can't
        // resolve `b` to a LocalId, so .field_heap_free / .field_use
        // emissions silently drop.
        try self.registerFnParams();
        try self.lowerBlock(body_node, cur);
        // Synthetic implicit-return at fn-body end.  Void fns that
        // fall through without an explicit `return` still need
        // transferRet to fire so post-defer checks (e.g. dangling
        // out-param heap pointers) run.  Cheap idempotent emit —
        // when the body already returned explicitly, cur is in a
        // fresh dead block and this stmt sits unreached.
        const last = self.tree.lastToken(body_node);
        try self.appendStmt(cur.*, .{
            .kind = .{ .ret = .{
                .value_kind = .plain,
                .is_borrowed_return_type = false,
                .is_literal_undef = false,
            } },
            .pos = self.posOfToken(last),
            .end_pos = self.posOfTokenEnd(last),
        });
    }

    fn registerFnParams(self: *Builder) !void {
        const tree = self.tree;
        const proto = self.fn_proto orelse return;
        var it = proto.iterate(tree);
        while (it.next()) |param| {
            const name_tok = param.name_token orelse continue;
            const name = tree.tokenSlice(name_tok);
            if (std.mem.eql(u8, name, "_")) continue;
            // Extract the param's declared base type (e.g. "Foo" from
            // `*const Foo`), resolving Self / @This() to the enclosing
            // type so methods inside `pub const Foo = struct { fn f(
            // self: *Self) ... }` get a type_name of "Foo".
            const type_name: ?[]const u8 = if (param.type_expr) |te|
                self.extractTypeName(te, self.self_type)
            else
                null;
            const is_pointer = if (param.type_expr) |te|
                self.typeIsPointer(te)
            else
                false;
            _ = try self.registerLocalWithPointerHint(
                name,
                self.posOfToken(name_tok),
                false,
                .other,
                null,
                type_name,
                is_pointer,
            );
        }
    }

    fn pushDefer(self: *Builder, body_node: Ast.Node.Index) !void {
        try self.deferred.append(self.gpa, .{ .kind = .normal, .body = body_node });
    }

    fn pushErrdefer(self: *Builder, body_node: Ast.Node.Index) !void {
        try self.deferred.append(self.gpa, .{ .kind = .err, .body = body_node });
    }

    /// Replay `defer` bodies (LIFO) into `cur`.  Doesn't pop — returns
    /// happen mid-function and subsequent code in the same lexical
    /// scope must still see the same defer set.  Called at function-
    /// fallthrough exit and at every `return`.  Skips `.err` entries
    /// since errdefers only fire on error returns (handled in
    /// `flushErrAndNormalDefers`).
    fn flushDefers(self: *Builder, cur: *BlockId) (std.mem.Allocator.Error)!void {
        var i = self.deferred.items.len;
        while (i > 0) {
            i -= 1;
            const entry = self.deferred.items[i];
            if (entry.kind == .normal) {
                try self.lowerStmt(entry.body, cur);
            }
        }
    }

    /// Error-path flush: walk the unified defer stack LIFO, firing
    /// BOTH errdefers and defers in declaration-reverse order.  This
    /// matches Zig's semantics — a `defer use(p)` declared AFTER
    /// an `errdefer free(p)` runs FIRST on error exit, avoiding a
    /// spurious UAF in the synthetic err_exit sink.  Used at
    /// synthetic try-error-exit blocks.
    fn flushErrAndNormalDefers(self: *Builder, cur: *BlockId) (std.mem.Allocator.Error)!void {
        var i = self.deferred.items.len;
        while (i > 0) {
            i -= 1;
            try self.lowerStmt(self.deferred.items[i].body, cur);
        }
    }

    /// Dispatch on statement node tag.  v1: handle decls, assigns,
    /// expression-statement calls, returns, if/while; everything else
    /// becomes a `.lowering_gap` placeholder.
    fn lowerStmt(self: *Builder, stmt_node: Ast.Node.Index, cur: *BlockId) std.mem.Allocator.Error!void {
        const tree = self.tree;
        const tag = tree.nodeTag(stmt_node);
        switch (tag) {
            .simple_var_decl, .local_var_decl, .aligned_var_decl, .global_var_decl => {
                try self.lowerVarDecl(stmt_node, cur);
            },
            .assign, .assign_destructure => {
                try self.lowerAssign(stmt_node, cur);
            },
            .@"return" => {
                // lowerReturn handles its own defer-flush ordering —
                // it has to interleave with try-error-exit / catch
                // forking when the return value has those at top level.
                try self.lowerReturn(stmt_node, cur);
            },
            .call, .call_one, .call_comma, .call_one_comma => {
                try self.lowerCallStmt(stmt_node, cur);
            },
            .@"defer" => {
                const body = tree.nodeData(stmt_node).node;
                try self.pushDefer(body);
            },
            .@"errdefer" => {
                const body = tree.nodeData(stmt_node).opt_token_and_node[1];
                try self.pushErrdefer(body);
            },
            .if_simple, .@"if" => try self.lowerIf(stmt_node, cur),
            .while_simple, .while_cont, .@"while" => try self.lowerWhile(stmt_node, cur),
            .for_simple, .@"for" => try self.lowerFor(stmt_node, cur),
            .@"switch", .switch_comma => try self.lowerSwitch(stmt_node, cur),
            .@"try" => try self.lowerTryStmt(stmt_node, cur),
            .@"catch" => try self.lowerCatchStmt(stmt_node, cur),
            .@"break" => try self.lowerBreakOrContinue(cur, .@"break", stmt_node),
            .@"continue" => try self.lowerBreakOrContinue(cur, .@"continue", stmt_node),
            // Divergent stmts: replace cur with a fresh dead block so
            // any caller-added edge from cur to a successor (e.g.
            // emitCatchFork wiring catch-body→merge after `catch
            // unreachable`) flows from an unreachable block.  Without
            // this, the diverged path's stale state pollutes the
            // merge join — e.g. `const buf = alloc(...) catch
            // unreachable; free(buf);` would lose buf's .heap origin
            // at the merge because the catch arm collapses to .plain.
            .unreachable_literal => cur.* = try self.newBlock(),
            .builtin_call, .builtin_call_two, .builtin_call_two_comma, .builtin_call_comma => {
                if (self.builtinIsDivergent(stmt_node)) {
                    cur.* = try self.newBlock();
                } else {
                    try self.lowerCallStmt(stmt_node, cur);
                }
            },
            // Nested blocks: recurse so empty blocks DON'T trigger
            // the conservative .plain collapse via lowering_gap.
            // Labeled forms (`blk: { ... break :blk; }`) get the
            // block-label scaffolding so `break :blk` can resolve.
            .block, .block_semicolon, .block_two, .block_two_semicolon => {
                if (self.blockLabelToken(stmt_node)) |lt| {
                    try self.lowerLabeledBlock(stmt_node, lt, cur);
                } else {
                    try self.lowerBlock(stmt_node, cur);
                }
            },
            else => {
                try self.appendStmt(cur.*, .{
                    .kind = .{ .lowering_gap = .{ .note = @tagName(tag) } },
                    .pos = self.posOf(stmt_node),
                    .end_pos = self.endPosOf(stmt_node),
                });
            },
        }
    }

    /// `if (cond) THEN [else ELSE]` → fork into two successor blocks,
    /// lower each branch into its own block, then join into a fresh
    /// merge block.  Subsequent statements emit into the merge block.
    ///
    /// We don't model the condition's truthiness — the abstract state
    /// must be valid on BOTH branches (this is conservative and matches
    /// our design: don't reason about branch-specific values).
    fn lowerIf(self: *Builder, if_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const if_data = tree.fullIf(if_node) orelse {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "if-extract" } },
                .pos = self.posOf(if_node),
                .end_pos = self.endPosOf(if_node),
            });
            return;
        };

        // Walk the condition for any local reads / address-of writes
        // before we branch — the condition runs before either arm and
        // its side effects (e.g. `&out` clearing .undef) must be
        // visible in BOTH successor states.
        try self.emitUsesInExpr(if_data.ast.cond_expr, cur.*, null);

        // Allocate the three successor blocks up-front.
        const then_block = try self.newBlock();
        const else_block = if (if_data.ast.else_expr.unwrap() != null) try self.newBlock() else null;
        const merge_block = try self.newBlock();

        // From `cur`: branch to then-block and (else-block OR merge directly
        // if no else clause — falling through is the same as an empty else).
        try self.addEdge(cur.*, then_block);
        try self.addEdge(cur.*, else_block orelse merge_block);

        // Lower the then branch.  `if (opt) |val|` payload is in scope
        // for the then-body only.  Reset at then-entry: when the if is
        // inside a loop body, the capture rebinds each iteration so
        // prior-iter state must not propagate.
        if (if_data.payload_token) |pt| try self.registerCapturesWith(pt, then_block);
        var then_cur = then_block;
        try self.lowerStmt(if_data.ast.then_expr, &then_cur);
        // Then-branch exits flow into merge.
        try self.addEdge(then_cur, merge_block);

        // Lower the else branch if present.  `else |err|` payload is
        // in scope for the else-body only.
        if (else_block) |eb| {
            if (if_data.error_token) |et| try self.registerCapturesWith(et, eb);
            var else_cur = eb;
            try self.lowerStmt(if_data.ast.else_expr.unwrap().?, &else_cur);
            try self.addEdge(else_cur, merge_block);
        }

        // Subsequent statements emit into the merge block.
        cur.* = merge_block;
    }

    /// `while (cond) BODY [else ELSE]` → produces a header block (where
    /// the condition is evaluated each iteration), a body block, and a
    /// merge block (post-loop).  Back-edge from body → header creates
    /// the loop — the analyzer's worklist iterates body's state into
    /// header until fixed point.
    ///
    /// We model the simplest valid loop CFG:
    ///   cur ─→ header ─→ body ─→ header (back-edge)
    ///                  ↘ merge (loop exit / else)
    fn lowerWhile(self: *Builder, while_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const while_data = tree.fullWhile(while_node) orelse {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "while-extract" } },
                .pos = self.posOf(while_node),
                .end_pos = self.endPosOf(while_node),
            });
            return;
        };

        // Walk the loop condition for .use/.assign side effects
        // before any branching.  Skip rules in emitUsesInExpr now
        // tolerate `arr.len` / `arr[..]` so this no longer drowns in
        // false positives.
        try self.emitUsesInExpr(while_data.ast.cond_expr, cur.*, null);

        const header = try self.newBlock();
        const body = try self.newBlock();
        const merge = try self.newBlock();

        // Edge: cur → header (loop entry)
        try self.addEdge(cur.*, header);

        // Header branches to body (when cond true) or merge (when false).
        try self.addEdge(header, body);
        try self.addEdge(header, merge);

        // Lower the body; on exit, back-edge to header.  Push loop
        // context so any `break`/`continue` inside lowers correctly.
        const label_slice: ?[]const u8 = if (while_data.label_token) |lt|
            tree.tokenSlice(lt)
        else
            null;
        try self.loop_stack.append(self.gpa, .{
            .header = header,
            .merge = merge,
            .label = label_slice,
        });
        // `while (opt) |x|` payload capture — register before body
        // and emit reset stmts at body entry so back-edges don't
        // propagate one iteration's state (e.g. .heap.dead from
        // `free(x)`) into the next iteration's view of the capture.
        if (while_data.payload_token) |pt| try self.registerCapturesWith(pt, body);
        var body_cur = body;
        try self.lowerStmt(while_data.ast.then_expr, &body_cur);
        _ = self.loop_stack.pop();
        try self.addEdge(body_cur, header);

        // Optional else block (runs once when cond becomes false).
        // We don't model the "runs only on natural exit, not on break" —
        // treat as falling through to merge.
        if (while_data.ast.else_expr.unwrap()) |else_expr| {
            const else_block = try self.newBlock();
            try self.addEdge(header, else_block);
            var else_cur = else_block;
            try self.lowerStmt(else_expr, &else_cur);
            try self.addEdge(else_cur, merge);
        }

        cur.* = merge;
    }

    /// `for (input) |x| BODY [else ELSE]` — structurally identical to a
    /// while loop for our purposes (header decides each iteration, body
    /// back-edges to header).  We don't model the iteration variable's
    /// origin (would need to track input's element-lifetime per item);
    /// the iterator binding gets registered as a fresh local with .plain
    /// init so subsequent uses are conservative.
    fn lowerFor(self: *Builder, for_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const for_data = tree.fullFor(for_node) orelse {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "for-extract" } },
                .pos = self.posOf(for_node),
                .end_pos = self.endPosOf(for_node),
            });
            return;
        };

        // Walk every input expression before any branching.
        for (for_data.ast.inputs) |input| {
            try self.emitUsesInExpr(input, cur.*, null);
        }

        const header = try self.newBlock();
        const body = try self.newBlock();
        const merge = try self.newBlock();

        try self.addEdge(cur.*, header);
        try self.addEdge(header, body);
        try self.addEdge(header, merge);

        const for_label: ?[]const u8 = if (for_data.label_token) |lt|
            tree.tokenSlice(lt)
        else
            null;
        try self.loop_stack.append(self.gpa, .{
            .header = header,
            .merge = merge,
            .label = for_label,
        });
        // For-loops always have a payload (`|x|` or `|x, idx|`).
        // Reset on iteration entry — see lowerWhile for rationale.
        try self.registerCapturesWith(for_data.payload_token, body);
        var body_cur = body;
        try self.lowerStmt(for_data.ast.then_expr, &body_cur);
        _ = self.loop_stack.pop();
        try self.addEdge(body_cur, header); // back-edge for fixed-point iteration

        if (for_data.ast.else_expr.unwrap()) |else_expr| {
            const else_block = try self.newBlock();
            try self.addEdge(header, else_block);
            var else_cur = else_block;
            try self.lowerStmt(else_expr, &else_cur);
            try self.addEdge(else_cur, merge);
        }

        cur.* = merge;
    }

    /// `switch (cond) { CASE => EXPR, ... }` — N-way fork.  Each case
    /// becomes a successor of `cur`; all cases join into a fresh merge
    /// block.  We don't model case-pattern matching or exhaustiveness;
    /// every case is treated as reachable from cur.
    fn lowerSwitch(self: *Builder, sw_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const sw = tree.fullSwitch(sw_node) orelse {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "switch-extract" } },
                .pos = self.posOf(sw_node),
                .end_pos = self.endPosOf(sw_node),
            });
            return;
        };

        // Walk the discriminant expression before any case branch.
        try self.emitUsesInExpr(sw.ast.condition, cur.*, null);

        const merge = try self.newBlock();

        if (sw.ast.cases.len == 0) {
            try self.addEdge(cur.*, merge);
            cur.* = merge;
            return;
        }

        for (sw.ast.cases) |case_node| {
            const case_full = tree.fullSwitchCase(case_node) orelse continue;
            const case_block = try self.newBlock();
            try self.addEdge(cur.*, case_block);
            // `.tag => |val| ...` capture binds inside this case only.
            if (case_full.payload_token) |pt| try self.registerCaptures(pt);
            var case_cur = case_block;
            try self.lowerStmt(case_full.ast.target_expr, &case_cur);
            try self.addEdge(case_cur, merge);
        }

        cur.* = merge;
    }

    /// `try expr` at statement position.  Lower `expr` on the success
    /// path (cur continues forward); add an error-exit edge to a sink
    /// block that replays errdefers + defers and terminates.  The sink
    /// has no successor — it represents the implicit `return error.X`.
    ///
    /// Phase 9 v1: we DON'T attach this error-exit edge to every
    /// `try` buried inside an expression (e.g. `const x = try foo()`).
    /// That would require expression-tree walks and would explode the
    /// CFG with sink blocks that don't enrich downstream analysis.
    /// Statement-position try alone is enough to model the common
    /// pattern `try foo();` for side-effect calls.
    fn lowerTryStmt(self: *Builder, try_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const inner = tree.nodeData(try_node).node;
        // Success path: side-effects of the wrapped expression.
        try self.lowerStmt(inner, cur);
        // Error path: synthetic sink.
        try self.emitTryErrorExit(cur, self.posOf(try_node));
    }

    /// Is this block node labeled (`blk: { ... }`)?  Returns the
    /// label-identifier token if so.  Block labels live at
    /// `main_token - 2` (identifier) + `main_token - 1` (`:`).
    fn blockLabelToken(self: *Builder, block_node: Ast.Node.Index) ?Ast.TokenIndex {
        const tree = self.tree;
        const main = tree.nodeMainToken(block_node);
        if (main < 2) return null;
        const tags = tree.tokens.items(.tag);
        if (tags[main - 1] != .colon) return null;
        if (tags[main - 2] != .identifier) return null;
        return main - 2;
    }

    /// If `expr` is a top-level labeled block at an expression
    /// position (`const x = blk: { ... }`, `return blk: {...}`,
    /// `x = blk: {...}`), lower its body in-place — advancing cur
    /// to the post-merge — and return true.  The caller then
    /// emits its decl/ret/assign on the post-merge cur, with an
    /// .unknown classification since we don't track which break
    /// path's value was taken.  Returns false for non-block exprs.
    /// If the labeled block has exactly one `break :label X` with
    /// a value, return X for classification.  Multiple distinct
    /// break values or none → null.
    fn singleLabeledBreakValue(
        self: *Builder,
        block_node: Ast.Node.Index,
        label_token: Ast.TokenIndex,
    ) ?Ast.Node.Index {
        const tree = self.tree;
        const label = tree.tokenSlice(label_token);
        const block_first = tree.firstToken(block_node);
        const block_last = tree.lastToken(block_node);

        var found: ?Ast.Node.Index = null;
        var node_idx: u32 = 1;
        while (node_idx < tree.nodes.len) : (node_idx += 1) {
            const node: Ast.Node.Index = @enumFromInt(node_idx);
            if (tree.nodeTag(node) != .@"break") continue;
            const ft = tree.firstToken(node);
            const lt = tree.lastToken(node);
            if (ft < block_first or lt > block_last) continue;
            const data = tree.nodeData(node).opt_token_and_opt_node;
            const lbl_tok = data[0].unwrap() orelse continue;
            if (!std.mem.eql(u8, tree.tokenSlice(lbl_tok), label)) continue;
            const val = data[1].unwrap() orelse continue; // bare `break :blk;`
            if (found != null) return null; // multiple breaks — ambiguous
            found = val;
        }
        return found;
    }

    fn maybeLowerLabeledBlockExpr(
        self: *Builder,
        expr: Ast.Node.Index,
        cur: *BlockId,
    ) !bool {
        const tree = self.tree;
        switch (tree.nodeTag(expr)) {
            .block, .block_semicolon, .block_two, .block_two_semicolon => {},
            else => return false,
        }
        const lt = self.blockLabelToken(expr) orelse return false;
        try self.lowerLabeledBlock(expr, lt, cur);
        return true;
    }

    /// `blk: { ... }` at statement position — push label context,
    /// lower body normally, pop, then sew the natural fallthrough
    /// edge cur → merge and continue from merge.  Any `break :blk`
    /// inside the body adds its own edge to merge via
    /// lowerBreakOrContinue.
    fn lowerLabeledBlock(
        self: *Builder,
        block_node: Ast.Node.Index,
        label_token: Ast.TokenIndex,
        cur: *BlockId,
    ) !void {
        const tree = self.tree;
        const label = tree.tokenSlice(label_token);
        const merge = try self.newBlock();
        try self.block_label_stack.append(self.gpa, .{ .label = label, .merge = merge });
        try self.lowerBlock(block_node, cur);
        _ = self.block_label_stack.pop();
        // Natural fallthrough — body completed without breaking.
        try self.addEdge(cur.*, merge);
        cur.* = merge;
    }

    /// `break`/`continue` — add an edge from cur to the innermost
    /// loop's merge (break) or header (continue), then redirect cur
    /// to a fresh dead block so any statements emitted after the
    /// break/continue don't leak into the actual flow.  Labeled
    /// break first searches the block-label stack, then loops.
    fn lowerBreakOrContinue(
        self: *Builder,
        cur: *BlockId,
        kind: enum { @"break", @"continue" },
        node: Ast.Node.Index,
    ) !void {
        const tree = self.tree;

        // `break/continue :name` — Ast data is opt_token_and_opt_node;
        // the OptionalTokenIndex points at the bare identifier (no
        // colon).  For labeled break, search block_label_stack first
        // (since blocks can only be break targets, never continue),
        // then fall through to loop_stack.  Done BEFORE the "no
        // loops" check so `break :blk` inside a labeled block (which
        // doesn't push onto loop_stack) still resolves correctly.
        const opt_label_tok = tree.nodeData(node).opt_token_and_opt_node[0];
        if (opt_label_tok.unwrap()) |lt| {
            const wanted = tree.tokenSlice(lt);
            // Block labels: break only.  Continue to a block label is
            // a compile error in Zig; defensively skip if encountered.
            if (kind == .@"break") {
                var i = self.block_label_stack.items.len;
                while (i > 0) {
                    i -= 1;
                    const ctx = self.block_label_stack.items[i];
                    if (std.mem.eql(u8, ctx.label, wanted)) {
                        try self.addEdge(cur.*, ctx.merge);
                        cur.* = try self.newBlock();
                        return;
                    }
                }
            }
            // Loop labels: walk inside-out.
            var i = self.loop_stack.items.len;
            while (i > 0) {
                i -= 1;
                const ctx = self.loop_stack.items[i];
                if (ctx.label) |lbl| {
                    if (std.mem.eql(u8, lbl, wanted)) {
                        const target = switch (kind) {
                            .@"break" => ctx.merge,
                            .@"continue" => ctx.header,
                        };
                        try self.addEdge(cur.*, target);
                        cur.* = try self.newBlock();
                        return;
                    }
                }
            }
            // No match in either stack.
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "labeled-break-no-loop" } },
                .pos = self.posOf(node),
                .end_pos = self.endPosOf(node),
            });
            return;
        }

        // Unlabeled: innermost loop.  Now `loop_stack` may be empty
        // (we don't pre-check anymore so labeled-break can resolve
        // via block_label_stack first); a truly unlabeled break
        // outside any loop is a Zig compile error, so handle
        // defensively with a gap.
        if (self.loop_stack.items.len == 0) {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "break-outside-loop" } },
                .pos = self.posOf(node),
                .end_pos = self.endPosOf(node),
            });
            return;
        }
        const ctx = self.loop_stack.items[self.loop_stack.items.len - 1];
        const target = switch (kind) {
            .@"break" => ctx.merge,
            .@"continue" => ctx.header,
        };
        try self.addEdge(cur.*, target);
        cur.* = try self.newBlock();
    }

    /// Build the synthetic error-exit sink for an in-expression `try`.
    /// Used by both `lowerTryStmt` and `lowerVarDecl` (when init is a
    /// top-level `.@"try"`).  The sink is a new block reachable from
    /// `from` with errdefer + defer replayed, terminated by a ret.
    fn emitTryErrorExit(self: *Builder, cur: *BlockId, pos: SrcPos) !void {
        // Split: success path continues in a FRESH block.  Without
        // this, subsequent stmts emitted into the original `cur`
        // would propagate their post-state into the err_exit sink
        // (via the cur→err_exit edge), causing the sink to see e.g.
        // post-defer-free state and fire spurious double-free.
        const err_exit = try self.newBlock();
        const post_try = try self.newBlock();
        try self.addEdge(cur.*, err_exit);
        try self.addEdge(cur.*, post_try);

        var err_cur = err_exit;
        try self.flushErrAndNormalDefers(&err_cur);
        try self.appendStmt(err_cur, .{
            .kind = .{ .ret = .{
                .value_kind = .unknown,
                .is_borrowed_return_type = self.is_borrowed_return_type,
            } },
            .pos = pos,
            // Synthetic ret — no source extent to highlight; fall back
            // to a single-column range via end_pos = pos.
            .end_pos = pos,
        });

        cur.* = post_try;
    }

    /// `lhs catch BODY` at statement position — forks into two paths:
    /// success (lhs's side effects only) and error (BODY runs).  Both
    /// join into a fresh merge block.  Unlike `try`, catch consumes
    /// the error; errdefers do NOT fire on the error edge.
    fn lowerCatchStmt(self: *Builder, catch_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const data = tree.nodeData(catch_node).node_and_node;
        // Success path: lhs's side effects emit into cur.
        try self.lowerStmt(data[0], cur);
        try self.emitCatchFork(catch_node, cur);
    }

    /// Append a catch-body fork to `cur`: one edge straight to merge
    /// (success), one through a new block where the catch body lowers,
    /// then both join.  `cur` advances to merge.  Used by
    /// `lowerCatchStmt`, `lowerVarDecl`, `lowerReturn`, `lowerAssign`
    /// — every position where `expr catch BODY` can appear at top
    /// level of an expression.
    ///
    /// `catch_node` is the `.@"catch"` Ast node itself (not its rhs)
    /// so we can also resolve the optional `|err|` payload — Zig
    /// AST doesn't surface it through a struct helper.
    fn emitCatchFork(self: *Builder, catch_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const body_node = tree.nodeData(catch_node).node_and_node[1];

        const catch_block = try self.newBlock();
        const merge = try self.newBlock();

        try self.addEdge(cur.*, catch_block);
        try self.addEdge(cur.*, merge);

        // `catch |err| BODY` — payload is `main_token + 2` when the
        // token immediately following `catch` is `|`.  Scope: body only.
        if (self.catchPayloadToken(catch_node)) |pt| {
            try self.registerCaptures(pt);
        }

        var catch_cur = catch_block;
        try self.lowerStmt(body_node, &catch_cur);
        try self.addEdge(catch_cur, merge);

        cur.* = merge;
    }

    fn catchPayloadToken(self: *Builder, catch_node: Ast.Node.Index) ?Ast.TokenIndex {
        const tree = self.tree;
        const main = tree.nodeMainToken(catch_node);
        const tags = tree.tokens.items(.tag);
        if (main + 1 >= tags.len) return null;
        if (tags[main + 1] != .pipe) return null;
        return main + 2;
    }

    fn lowerVarDecl(self: *Builder, decl_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const var_decl = tree.fullVarDecl(decl_node) orelse {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "var_decl-extract" } },
                .pos = self.posOf(decl_node),
                .end_pos = self.endPosOf(decl_node),
            });
            return;
        };
        const name_tok = var_decl.ast.mut_token + 1;
        if (tree.tokens.items(.tag)[name_tok] != .identifier) {
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "var_decl-no-name" } },
                .pos = self.posOf(decl_node),
                .end_pos = self.endPosOf(decl_node),
            });
            return;
        }
        const name = tree.tokenSlice(name_tok);
        const is_array = if (var_decl.ast.type_node.unwrap()) |tn|
            self.typeIsStackArray(tn)
        else
            false;
        const is_pointer = if (var_decl.ast.type_node.unwrap()) |tn|
            self.typeIsPointer(tn)
        else
            false;

        const init_opt = var_decl.ast.init_node.unwrap();

        // Top-level labeled-block init (`const x = blk: { ... };`) —
        // lower the body FIRST so its side effects + break paths run
        // before the binding takes effect.  cur advances to the
        // post-merge; the .decl emits there with .unknown init_kind.
        var init_was_labeled_block = false;
        if (init_opt) |init| {
            init_was_labeled_block = try self.maybeLowerLabeledBlockExpr(init, cur);
        }

        const init_kind: ExprKind = if (init_opt) |init|
            self.classifyExpr(init)
        else
            .plain;

        // Derive init_hint from the classification — avoids a second
        // classifyExpr call (which would double-mint Arena/Heap ids).
        var effective_init_kind = init_kind;
        const init_hint: InitHint = blk: {
            switch (init_kind) {
                .arena_init => break :blk .arena_local,
                .heap_alloc => break :blk .heap_local,
                // Allocator-provenance: when init_kind is .copy_of(src)
                // (set by classifyExpr's .allocator()-detection path,
                // or by simple aliasing `const a2 = a;`), inherit
                // .arena_allocator from the source if it's arena-bound.
                // Lets `.alloc()` calls through any depth of allocator
                // alias produce arena memory.
                .copy_of => |src| {
                    const src_hint = self.locals.items[@intFromEnum(src)].init_hint;
                    if (src_hint == .arena_local or src_hint == .arena_allocator) {
                        break :blk .arena_allocator;
                    }
                },
                else => {},
            }
            // Aliased noreturn fn: `const exit = std.process.exit;`
            // Lets later call sites that use the alias terminate
            // their block.
            if (init_opt) |i| if (self.initIsNoreturnAlias(i)) break :blk .noreturn_alias;
            // Struct-wrap propagation: `var ma = Wrapper{ .inner =
            // arena };` — ma carries arena via its field.  Override
            // init_kind to .copy_of(wrapper) so transferDecl
            // propagates arena's origin to ma at state-tracking time
            // (the hint alone only affects classify-time decisions).
            if (init_opt) |i| if (self.initWrapsResourceLocalRef(i)) |hit| {
                effective_init_kind = .{ .copy_of = hit.local };
                break :blk hit.hint;
            };
            break :blk .other;
        };
        // Function-pointer binding: `const op = some_fn;` where
        // some_fn is in our annotation DB.  Records the binding so
        // call sites `op(args)` resolve through to some_fn's
        // annotation / takes / is_noreturn.
        const bound_fn_name: ?[]const u8 = if (init_opt) |i| self.boundFnName(i) else null;
        // Type annotation on the decl (`var x: Foo = ...`) — extracted
        // for receiver-type tracking.  When absent, fall back to
        // inferring the type from the init expression — recognises
        // `T.init(...)` / `try T.init(...)` and `T{...}` shapes so
        // `var owner = try Owner.init(...)` still resolves to "Owner".
        // Implicit-typed decls without a recognisable constructor
        // leave type_name null; the lookup falls back to bare-name.
        const decl_type_name: ?[]const u8 = blk: {
            if (var_decl.ast.type_node.unwrap()) |tn| {
                break :blk self.extractTypeName(tn, self.self_type);
            }
            if (init_opt) |init| {
                break :blk self.inferTypeNameFromInit(init);
            }
            break :blk null;
        };
        const local = try self.registerLocalWithPointerHint(
            name,
            self.posOfToken(name_tok),
            is_array,
            init_hint,
            bound_fn_name,
            decl_type_name,
            is_pointer,
        );

        // Emit .use stmts for every local read by the init expression
        // (before the .decl so the read is checked against pre-decl state).
        // Skip emitUsesInExpr when init was a labeled block — the
        // block's body already lowered each inner stmt (with its
        // own .use/.assign emissions).  Walking the whole init
        // expression's tokens would incorrectly emit .use for LHS
        // identifiers of inner assigns.
        if (!init_was_labeled_block) {
            if (init_opt) |init| try self.emitUsesInExpr(init, cur.*, null);
        }

        try self.appendStmt(cur.*, .{
            .kind = .{ .decl = .{ .local = local, .init_kind = effective_init_kind } },
            .pos = self.posOf(decl_node),
            .end_pos = self.endPosOf(decl_node),
        });

        // Struct-literal RHS: unpack so aliased fields buried in the
        // literal get their own field_assign keyed by name.  Symmetric
        // with lowerAssign — `var c: T = .{ .data = buf }` registers
        // `(c, "data") → buf's origin` so a later `c.data` read sees
        // buf's freed state.  Skipped for labeled-block inits (the
        // inner stmts already lowered themselves).
        if (init_opt) |init| if (!init_was_labeled_block) {
            try self.unpackStructInitFields(cur.*, local, null, init,
                self.posOf(decl_node), self.endPosOf(decl_node));
        };

        // Init-position try/catch: now that the decl has emitted, model
        // the same CFG side-effects we'd get if the init had appeared
        // at statement position.  We don't walk arbitrarily-nested try
        // inside larger expressions — only top-level forms.  These
        // cover the common cases (`const x = try foo()`, `const x =
        // foo() catch ...`); buried try inside arithmetic etc. is rare
        // and unmodeled (yields a sink-less success-only path).
        if (init_opt) |init| {
            try self.lowerInitSideEffects(init, cur);
        }
    }

    /// Walk an init / rhs expression for top-level catch / try / orelse
    /// forms whose bodies have side effects (defers fire, locals
    /// initialize, arena.deinit() runs).  Without lowering these, the
    /// abstract state at the decl's post-position reflects only the
    /// success path — a catch body that does `arena.deinit(); return
    /// throwValue(log.toJS());` would never be seen, hiding a UAK.
    ///
    /// Handles:
    ///   - `expr catch BODY` → emitCatchFork
    ///   - `try expr`        → emitTryErrorExit
    ///   - `expr orelse BODY` → recurse into lhs (catch may live there),
    ///     plus lower orelse-BODY as a fork of its own
    ///
    /// Recursion bounded by AST depth; cheap.
    fn lowerInitSideEffects(self: *Builder, init: Ast.Node.Index, cur: *BlockId) (std.mem.Allocator.Error)!void {
        const tree = self.tree;
        switch (tree.nodeTag(init)) {
            .@"try" => try self.emitTryErrorExit(cur, self.posOf(init)),
            .@"catch" => try self.emitCatchFork(init, cur),
            .@"orelse" => {
                const data = tree.nodeData(init).node_and_node;
                // lhs may itself contain a top-level catch/try whose
                // body has side effects (the common
                // `expr catch {...} orelse {...}` shape).
                try self.lowerInitSideEffects(data[0], cur);
                // Fork the orelse body: success edge (optional was
                // non-null) and orelse-body edge.  Body is BODY=data[1].
                try self.emitOrelseFork(data[1], cur);
            },
            else => {},
        }
    }

    /// Like emitCatchFork but for an `orelse BODY`.  The body runs
    /// when the optional resolves to null.  Same join shape.
    fn emitOrelseFork(self: *Builder, body_node: Ast.Node.Index, cur: *BlockId) !void {
        const orelse_block = try self.newBlock();
        const merge = try self.newBlock();
        try self.addEdge(cur.*, orelse_block);
        try self.addEdge(cur.*, merge);
        var ob_cur = orelse_block;
        try self.lowerStmt(body_node, &ob_cur);
        try self.addEdge(ob_cur, merge);
        cur.* = merge;
    }

    /// `LHS = RHS;` — when LHS is a known simple-identifier local, emit
    /// a real `.assign` so the analyzer can update origin tracking.
    /// Otherwise (field access, deref, destructuring) fall back to a
    /// lowering_gap so locals collapse conservatively to .plain.
    ///
    /// Either way, if the RHS has a top-level `try` or `catch`, emit
    /// the same error-exit / fork helpers we use in init/return
    /// positions — those error-path CFG edges are independent of
    /// whether we successfully tracked the target.
    fn lowerAssign(self: *Builder, assign_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const tag = tree.nodeTag(assign_node);

        // Destructuring (`a, b = pair` / `const a, const b = pair()`).
        // Multi-target — we can't classify per-slot, so each target
        // gets .unknown.  But registering the locals (in the var-decl
        // form) and emitting per-target .assign / .decl beats one big
        // gap that collapsed everything to .plain.
        if (tag == .assign_destructure) {
            try self.lowerAssignDestructure(assign_node, cur);
            return;
        }

        const data = tree.nodeData(assign_node).node_and_node;
        const lhs = data[0];
        const rhs = data[1];

        // Resolve target: only simple identifier LHS for now.
        const target_local: ?LocalId = if (tree.nodeTag(lhs) == .identifier)
            self.name_to_local.get(tree.tokenSlice(tree.nodeMainToken(lhs)))
        else
            null;

        // Top-level labeled-block rhs (`x = blk: { ... };`) — lower
        // its body in-place, advancing cur, before the .assign emits.
        // When this fires, the body's inner stmts already emitted
        // their own .use / .assign / .free; walking the same rhs again
        // via emitUsesInExpr would double-count those tokens and, e.g.
        // emit a .use(host) at the labeled-block's opening AFTER the
        // body already lowered an `allocator.free(host)`.  Symmetric
        // to the same guard in lowerVarDecl.
        const rhs_was_labeled_block = try self.maybeLowerLabeledBlockExpr(rhs, cur);


        if (target_local) |t| {
            // .use stmts for rhs reads, skipping the LHS itself
            // (assignment writes LHS, not reads it).
            if (!rhs_was_labeled_block) {
                try self.emitUsesInExpr(rhs, cur.*, t);
            }
            try self.appendStmt(cur.*, .{
                .kind = .{ .assign = .{
                    .target = t,
                    .rhs_kind = self.classifyExpr(rhs),
                } },
                .pos = self.posOf(assign_node),
                .end_pos = self.endPosOf(assign_node),
            });
            // Struct-literal RHS: unpack so aliased fields buried in
            // the literal get their own field_assign keyed by name.
            // `container = .{ .ptr = buf }` registers
            // `(container, "ptr") → buf's origin` so a later
            // `container.ptr` read sees buf's freed state.
            try self.unpackStructInitFields(cur.*, t, null, rhs,
                self.posOf(assign_node), self.endPosOf(assign_node));
        } else if (self.fieldLhsFor(lhs)) |fref| {
            // `obj.field = RHS` where obj is a known local — emit
            // .field_assign so the field's origin is tracked
            // separately.  Catches store-then-free-then-use of a
            // struct field.
            if (!rhs_was_labeled_block) {
                try self.emitUsesInExpr(rhs, cur.*, null);
            }
            try self.appendStmt(cur.*, .{
                .kind = .{ .field_assign = .{
                    .parent = fref.parent,
                    .name = fref.name,
                    .rhs_kind = self.classifyExpr(rhs),
                } },
                .pos = self.posOf(assign_node),
                .end_pos = self.endPosOf(assign_node),
            });
            // Nested struct-literal unpack for the field LHS, e.g.
            // `install.ca = .{ .str = buf }` → field_assign on
            // `(install, "ca.str")`.  PR #25563 shape.
            try self.unpackStructInitFields(cur.*, fref.parent, fref.name, rhs,
                self.posOf(assign_node), self.endPosOf(assign_node));
            // Escape-via-out-param: `out.field = X` where `out` is a
            // pointer-typed parameter writes through to caller
            // storage.  If X's origin is a function-local arena /
            // stack reference, that lifetime now reaches the caller
            // — fire the same escape diagnostics as a borrowed-shape
            // return.
            if (self.locals.items[@intFromEnum(fref.parent)].is_pointer) {
                try self.appendStmt(cur.*, .{
                    .kind = .{ .out_param_write = .{
                        .out = fref.parent,
                        .value_kind = self.classifyExpr(rhs),
                    } },
                    .pos = self.posOf(assign_node),
                    .end_pos = self.endPosOf(assign_node),
                });
            }
        } else if (self.derefOfPointerLocal(lhs)) |out_local| {
            // `<local>.* = RHS` — when local is pointer-typed, this
            // writes through the pointer to caller-visible storage.
            // Mirror the field-of-pointer case above: emit a
            // pointer_write to clear .undef on the pointer and an
            // out_param_write for the escape check.
            if (!rhs_was_labeled_block) {
                try self.emitUsesInExpr(rhs, cur.*, null);
            }
            try self.appendStmt(cur.*, .{
                .kind = .{ .pointer_write = .{ .target = out_local } },
                .pos = self.posOf(assign_node),
                .end_pos = self.endPosOf(assign_node),
            });
            try self.appendStmt(cur.*, .{
                .kind = .{ .out_param_write = .{
                    .out = out_local,
                    .value_kind = self.classifyExpr(rhs),
                } },
                .pos = self.posOf(assign_node),
                .end_pos = self.endPosOf(assign_node),
            });
        } else if (tree.nodeTag(lhs) == .identifier and
            std.mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(lhs)), "_"))
        {
            // Discard: `_ = expr;`.  Reads the RHS, writes nothing.
            // CRUCIALLY we must NOT emit a .lowering_gap here — gap
            // collapses every local to .plain (since it represents
            // "we don't know what this stmt did").  `_ = x` is a
            // common idiom (`_ = arg; // autofix`) sprinkled all over
            // real codebases; treating each as a state wipe defeats
            // heap / arena tracking everywhere downstream.
            try self.emitUsesInExpr(rhs, cur.*, null);
            // If RHS is a call, its @takes-ownership / arena-kill
            // side effects must still fire.  `_ = h.markInactive();`
            // would otherwise miss the inter-procedural UAF.
            try self.applyTopLevelCallEffects(rhs, cur);
        } else {
            // Untracked target (e.g. `@field(obj, ...) = X`,
            // `arr[i] = X`).  For any known local mentioned anywhere in
            // the LHS expression, treat the assignment as a write to
            // that local — `obj.field = X` only type-checks if `obj` is
            // initialized, so clearing its .undef state is sound.
            try self.emitWritesInLhs(lhs, cur.*);
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "assign-target" } },
                .pos = self.posOf(assign_node),
                .end_pos = self.endPosOf(assign_node),
            });
        }

        // Mirror the init-position try/catch dispatch.
        switch (tree.nodeTag(rhs)) {
            .@"try" => try self.emitTryErrorExit(cur, self.posOf(rhs)),
            .@"catch" => try self.emitCatchFork(rhs, cur),
            else => {},
        }
    }

    /// `a, b = pair()` or `const a, const b = pair()`.  Per-variable:
    /// pure-identifier targets emit `.assign` against the resolved
    /// local; var-decl targets (`const x`) register a new local and
    /// emit `.decl`.  All rhs classifications are .unknown — we don't
    /// match tuple slots to types.  The rhs's top-level try/catch /
    /// labeled-block side-effects ARE lowered (once, before the
    /// per-target emissions), matching plain-assign semantics.
    fn lowerAssignDestructure(
        self: *Builder,
        assign_node: Ast.Node.Index,
        cur: *BlockId,
    ) !void {
        const tree = self.tree;
        const full = tree.assignDestructure(assign_node);
        const rhs = full.ast.value_expr;

        // Labeled-block expression rhs — lower body first.
        if (try self.maybeLowerLabeledBlockExpr(rhs, cur)) {}


        for (full.ast.variables) |var_node| {
            const vtag = tree.nodeTag(var_node);
            switch (vtag) {
                .identifier => {
                    const name = tree.tokenSlice(tree.nodeMainToken(var_node));
                    if (self.name_to_local.get(name)) |t| {
                        try self.appendStmt(cur.*, .{
                            .kind = .{ .assign = .{ .target = t, .rhs_kind = .unknown } },
                            .pos = self.posOf(var_node),
                            .end_pos = self.endPosOf(var_node),
                        });
                    } else {
                        try self.appendStmt(cur.*, .{
                            .kind = .{ .lowering_gap = .{ .note = "destructure-unresolved" } },
                            .pos = self.posOf(var_node),
                            .end_pos = self.endPosOf(var_node),
                        });
                    }
                },
                .simple_var_decl,
                .local_var_decl,
                .aligned_var_decl,
                .global_var_decl,
                => {
                    const vd = tree.fullVarDecl(var_node) orelse continue;
                    const name_tok = vd.ast.mut_token + 1;
                    if (tree.tokens.items(.tag)[name_tok] != .identifier) continue;
                    const name = tree.tokenSlice(name_tok);
                    const local = try self.registerLocal(name, self.posOfToken(name_tok));
                    try self.appendStmt(cur.*, .{
                        .kind = .{ .decl = .{ .local = local, .init_kind = .unknown } },
                        .pos = self.posOf(var_node),
                        .end_pos = self.endPosOf(var_node),
                    });
                },
                else => {
                    try self.appendStmt(cur.*, .{
                        .kind = .{ .lowering_gap = .{ .note = "destructure-target" } },
                        .pos = self.posOf(var_node),
                        .end_pos = self.endPosOf(var_node),
                    });
                },
            }
        }

        // Mirror plain assign: rhs try/catch dispatch comes after the
        // per-target emissions (so the success path has the assigns
        // visible before the error-exit / catch fork branches off).
        switch (tree.nodeTag(rhs)) {
            .@"try" => try self.emitTryErrorExit(cur, self.posOf(rhs)),
            .@"catch" => try self.emitCatchFork(rhs, cur),
            else => {},
        }
    }

    fn lowerReturn(self: *Builder, ret_node: Ast.Node.Index, cur: *BlockId) !void {
        const tree = self.tree;
        const data = tree.nodeData(ret_node);
        const value_opt = data.opt_node.unwrap();

        // Top-level try/catch in the returned expression — model the
        // error path BEFORE flushing defers (so the synthetic sink and
        // the merge block both get the right view of state).  The
        // err-exit sink does its own flushErrAndNormalDefers; the
        // catch fork advances cur to a merge where we continue the
        // success-path return.
        if (value_opt) |expr| {
            switch (tree.nodeTag(expr)) {
                .@"try" => try self.emitTryErrorExit(cur, self.posOf(expr)),
                .@"catch" => try self.emitCatchFork(expr, cur),
                else => {},
            }
            // Top-level labeled-block return (`return blk: { ... };`)
            // — lower body in-place so side effects + breaks run
            // before the return.  cur advances to post-merge; the
            // ret then emits there.
            if (try self.maybeLowerLabeledBlockExpr(expr, cur)) {}

            // Top-level switch return (`return switch (x) { ... .err
            // => { free; return error.Y } ... };`) — fork each arm's
            // body off `cur` as its own basic block so diverging arms
            // (those whose bodies `return` / `unreachable`) get their
            // errdefer/defer flushes and any UAF/double-free in their
            // statements modeled.  The outer .ret still emits from
            // `cur`, but arm-side-effects no longer hide inside an
            // unwalked expression.
            try self.maybeLowerReturnSwitchArms(expr, cur);
        }

        // Zig semantics: the return value is EVALUATED FIRST, then
        // defers fire, then the function actually exits.  Emit .use
        // stmts for the return value's reads BEFORE flushing defers
        // so a `defer free(buf); return use(buf);` pattern doesn't
        // see buf as already-freed at .use time.
        const value_kind: ExprKind = if (value_opt) |expr|
            self.classifyExpr(expr)
        else
            .plain;
        if (value_opt) |expr| try self.emitUsesInExpr(expr, cur.*, null);

        // Now flush defers — fires after the .use's, before the .ret.
        //
        // `return error.X` (or `return .{...}` resolving to an error-only
        // path) returns an error value, so Zig fires errdefers too.
        // Detect the syntactic `error.X` shape and use the error-path
        // flush; everything else uses the normal-only flush.  This is
        // conservative — `return foo()` where `foo()` returns an error
        // also fires errdefers, but we can't tell that from the AST
        // without callee resolution.  Catching the literal case is the
        // common bug shape (`errdefer free(p); return error.X` after an
        // explicit free of `p` is a textbook double-free).
        const value_is_literal_error = if (value_opt) |expr|
            isLiteralErrorReturn(tree, expr)
        else
            false;
        if (value_is_literal_error) {
            try self.flushErrAndNormalDefers(cur);
        } else {
            try self.flushDefers(cur);
        }

        // Multi-borrow composite returns: classifyExpr captures only
        // the first borrow in `value_kind`.  Walk the return value
        // again for ANY ADDITIONAL borrows (skipping the primary)
        // and emit a per-local .composite_escape check before the
        // .ret.  Without this, `return .{ .a = &x, .b = &y };` would
        // only flag x.
        //
        // Only run when value_kind ITSELF is a borrow-shape — that
        // tells us the return value is a composite-borrow construct,
        // not a call.  Skipping for .unknown / .owned / etc. avoids
        // false positives on `return foo(alloc, &local)` where
        // `&local` is just a call arg, not part of the return value.
        const primary_local: ?LocalId = switch (value_kind) {
            .stack_ref => |l| l,
            .composite_borrow => |l| l,
            else => null,
        };
        if (primary_local != null) {
            if (value_opt) |expr| {
                try self.emitAdditionalEscapeChecks(expr, cur.*, primary_local);
            }
        }

        // Detect `return undefined;` — a literal sentinel return,
        // not an undef-leak through a variable.
        const is_literal_undef = if (value_opt) |expr| blk: {
            if (tree.nodeTag(expr) != .identifier) break :blk false;
            const tok = tree.nodeMainToken(expr);
            break :blk std.mem.eql(u8, tree.tokenSlice(tok), "undefined");
        } else false;

        try self.appendStmt(cur.*, .{
            .kind = .{ .ret = .{
                .value_kind = value_kind,
                .is_borrowed_return_type = self.is_borrowed_return_type,
                .is_literal_undef = is_literal_undef,
            } },
            .pos = self.posOf(ret_node),
            .end_pos = self.endPosOf(ret_node),
        });
        // Return terminates the block — advance cur to a fresh dead
        // block so any addEdge our caller does (e.g. lowerIf wiring
        // an else-branch into the merge) flows from an unreachable
        // block, not the live ret block.  Without this, the pre-
        // return state leaks into the merge join and causes false
        // positives on locals that were only set on the non-return
        // branches.
        cur.* = try self.newBlock();
    }

    /// True for builtin calls that don't return — these terminate
    /// the basic block.  `unreachable` is already handled as a
    /// literal one level up in lowerStmt.
    /// For builtin calls that produce a value aliasing one of their
    /// args' underlying storage (`@ptrCast(x)`, `@bitCast(x)`,
    /// `@alignCast(x)`, `@constCast(x)`, `@volatileCast(x)`,
    /// `@addrSpaceCast(x)`, `@as(T, x)`, `@fieldParentPtr(name, p)`),
    /// return the AST node of the SOURCE argument so classifyExpr
    /// can recursively classify it.  The result's origin is
    /// whatever the source's was — alloc tracking flows through.
    fn transparentCastSource(self: *Builder, call_node: Ast.Node.Index) ?Ast.Node.Index {
        const tree = self.tree;
        const tok = tree.nodeMainToken(call_node);
        const name = tree.tokenSlice(tok);

        const SingleArg = enum { last };
        const LastArg = enum { last };
        const kind: union(enum) {
            single: SingleArg,
            last: LastArg,
            none,
        } = blk: {
            // Single-arg casts (arg 0 is the source).
            if (std.mem.eql(u8, name, "@ptrCast") or
                std.mem.eql(u8, name, "@bitCast") or
                std.mem.eql(u8, name, "@alignCast") or
                std.mem.eql(u8, name, "@constCast") or
                std.mem.eql(u8, name, "@volatileCast") or
                std.mem.eql(u8, name, "@addrSpaceCast"))
                break :blk .{ .single = .last };
            // Two-arg builtins where the source/pointer is the LAST arg:
            //   @as(T, x), @fieldParentPtr(name, ptr).
            if (std.mem.eql(u8, name, "@as") or
                std.mem.eql(u8, name, "@fieldParentPtr"))
                break :blk .{ .last = .last };
            break :blk .none;
        };

        if (kind == .none) return null;

        // Extract the LAST arg, which is the source/pointer for all
        // patterns we care about.  Two AST shapes to handle:
        //   .builtin_call_two[_comma]   — up to 2 args inline
        //   .builtin_call[_comma]       — N args via extra_range
        switch (tree.nodeTag(call_node)) {
            .builtin_call_two, .builtin_call_two_comma => {
                const d = tree.nodeData(call_node).opt_node_and_opt_node;
                if (d[1].unwrap()) |a| return a;
                if (d[0].unwrap()) |a| return a;
                return null;
            },
            .builtin_call, .builtin_call_comma => {
                const d = tree.nodeData(call_node).extra_range;
                const s: u32 = @intFromEnum(d.start);
                const e: u32 = @intFromEnum(d.end);
                if (e == s) return null;
                return @as(Ast.Node.Index, @enumFromInt(tree.extra_data[e - 1]));
            },
            else => return null,
        }
    }

    fn builtinIsDivergent(self: *Builder, call_node: Ast.Node.Index) bool {
        const tree = self.tree;
        const tok = tree.nodeMainToken(call_node);
        const slice = tree.tokenSlice(tok);
        return std.mem.eql(u8, slice, "@panic") or std.mem.eql(u8, slice, "@trap");
    }

    const WrapHit = struct { local: LocalId, hint: InitHint };

    /// If `init_node` is a struct-literal whose field values include
    /// a known arena_local or heap_local, return the strongest hit
    /// (source local + its hint).  Caller overrides init_kind to
    /// `.copy_of(hit.local)` so transferDecl propagates the wrapped
    /// resource's origin to the new local — composite-borrow
    /// checks then fire correctly on methods called on the wrapper.
    fn initWrapsResourceLocalRef(self: *Builder, init_node: Ast.Node.Index) ?WrapHit {
        const tree = self.tree;
        switch (tree.nodeTag(init_node)) {
            .struct_init, .struct_init_comma, .struct_init_one, .struct_init_one_comma,
            .struct_init_dot, .struct_init_dot_comma, .struct_init_dot_two, .struct_init_dot_two_comma,
            => {},
            else => return null,
        }
        const first = tree.firstToken(init_node);
        const last = tree.lastToken(init_node);
        const tags = tree.tokens.items(.tag);
        var result: ?WrapHit = null;
        var t: Ast.TokenIndex = first;
        while (t <= last) : (t += 1) {
            if (tags[t] != .identifier) continue;
            if (t > 0 and tags[t - 1] == .period) continue; // field name
            const name = tree.tokenSlice(t);
            const id = self.name_to_local.get(name) orelse continue;
            const hint = self.locals.items[@intFromEnum(id)].init_hint;
            switch (hint) {
                .arena_local => return .{ .local = id, .hint = .arena_local },
                .heap_local => result = .{ .local = id, .hint = .heap_local },
                else => {},
            }
        }
        return result;
    }

    /// If `name` matches a local with a function-pointer binding,
    /// return the bound fn's name.  Otherwise return `name` unchanged.
    /// Lets `const op = some_fn; op(args)` resolve to some_fn's
    /// annotation at call sites.
    fn resolveBoundCallee(self: *Builder, name: []const u8) []const u8 {
        const id = self.name_to_local.get(name) orelse return name;
        return self.locals.items[@intFromEnum(id)].bound_fn_name orelse name;
    }

    /// If `init_node` is a bare identifier that names an annotated
    /// fn (or any fn present in our DB — annotation can be null
    /// when only `@takes`/`is_noreturn` is set), return the fn's
    /// name slice.  Used to record function-pointer bindings so
    /// call sites via the local resolve to the original fn.
    fn boundFnName(self: *Builder, init_node: Ast.Node.Index) ?[]const u8 {
        const tree = self.tree;
        if (tree.nodeTag(init_node) != .identifier) return null;
        const name = tree.tokenSlice(tree.nodeMainToken(init_node));
        const db = self.db orelse return null;
        if (db.lookup(name) == null) return null;
        return name;
    }

    /// True iff `init_node`'s source text ends with one of the
    /// known-noreturn callee chains — set on the declaring local's
    /// init_hint so subsequent calls through the alias terminate.
    fn initIsNoreturnAlias(self: *Builder, init_node: Ast.Node.Index) bool {
        const tree = self.tree;
        const first = tree.firstToken(init_node);
        const last = tree.lastToken(init_node);
        const start = tree.tokens.items(.start)[first];
        const last_start = tree.tokens.items(.start)[last];
        const last_len = tree.tokenSlice(last).len;
        const text = tree.source[start .. last_start + last_len];
        for (known_noreturn_chains) |pat| {
            if (std.mem.endsWith(u8, text, pat)) return true;
        }
        return false;
    }

    /// Apply free / arena-kill side effects of a top-level call
    /// expression appearing in any context that's not a bare-stmt
    /// (var-decl init, assign RHS, return value, discard RHS).
    /// Returns true if anything was emitted; caller may use this to
    /// decide whether to additionally emit a use/gap.  Does NOT
    /// terminate the block for noreturn — callers handle that.
    fn applyTopLevelCallEffects(self: *Builder, expr_node: Ast.Node.Index, cur: *BlockId) (std.mem.Allocator.Error)!void {
        const tree = self.tree;
        // Walk through `try` / `catch` wrappers — they don't change
        // which call's effects fire on success path.
        var node = expr_node;
        while (true) switch (tree.nodeTag(node)) {
            .@"try" => node = tree.nodeData(node).node,
            .@"catch" => node = tree.nodeData(node).node_and_node[0],
            else => break,
        };
        switch (tree.nodeTag(node)) {
            .call, .call_one, .call_comma, .call_one_comma => {},
            else => return,
        }
        // Re-use the same dispatch logic as lowerCallStmt.  Pattern-
        // matched arena/heap kills already detected by lowerCallStmt
        // for bare-stmt calls — here we ALSO need @takes effects.
        if (self.takesOwnershipFreedLocal(node)) |freed| {
            try self.appendStmt(cur.*, .{
                .kind = .{ .heap_free = .{ .freed_local = freed, .fallback_hid = blk_h: {
                    const h: abstract_state.HeapId = @enumFromInt(self.next_heap);
                    self.next_heap += 1;
                    break :blk_h h;
                } } },
                .pos = self.posOf(node),
                .end_pos = self.endPosOf(node),
            });
            return;
        }
        if (self.takesOwnershipFreedField(node)) |fref| {
            try self.appendStmt(cur.*, .{
                .kind = .{ .field_heap_free = .{ .parent = fref.parent, .name = fref.name, .fallback_hid = blk_hid: {
                    const h: abstract_state.HeapId = @enumFromInt(self.next_heap);
                    self.next_heap += 1;
                    break :blk_hid h;
                } } },
                .pos = self.posOf(node),
                .end_pos = self.endPosOf(node),
            });
            return;
        }
        {
            var emissions: std.ArrayListUnmanaged(CalleeFieldFree) = .empty;
            defer emissions.deinit(self.gpa);
            try self.collectCalleeFieldFrees(node, self.gpa, &emissions);
            if (emissions.items.len > 0) {
                for (emissions.items) |em| {
                    try self.appendStmt(cur.*, .{
                        .kind = .{ .field_heap_free = .{ .parent = em.parent, .name = em.field, .fallback_hid = blk_hid: {
                            const h: abstract_state.HeapId = @enumFromInt(self.next_heap);
                            self.next_heap += 1;
                            break :blk_hid h;
                        } } },
                        .pos = self.posOf(node),
                        .end_pos = self.endPosOf(node),
                    });
                }
                return;
            }
        }
    }

    fn lowerCallStmt(self: *Builder, call_node: Ast.Node.Index, cur: *BlockId) !void {
        // Detect arena.deinit() patterns; otherwise emit nothing
        // (call has no side-effect from our pov).
        const tree = self.tree;
        const first = tree.firstToken(call_node);
        const last = tree.lastToken(call_node);
        const start = tree.tokens.items(.start)[first];
        const last_start = tree.tokens.items(.start)[last];
        const last_len = tree.tokenSlice(last).len;
        const end: usize = last_start + last_len;
        const text = tree.source[start..end];

        if (anyPatternMatches(text, self.config.arena_kill_patterns)) {
            const recv_local = self.firstIdentifierLocal(text) orelse {
                try self.appendStmt(cur.*, .{
                    .kind = .{ .lowering_gap = .{ .note = "deinit-no-receiver" } },
                    .pos = self.posOf(call_node),
                    .end_pos = self.endPosOf(call_node),
                });
                return;
            };
            try self.appendStmt(cur.*, .{
                .kind = .{ .arena_kill = .{ .arena_local = recv_local } },
                .pos = self.posOf(call_node),
                .end_pos = self.endPosOf(call_node),
            });
            // For value-typed receivers with their own `deinit`
            // (e.g. `Utf8.deinit` annotated `@takes ownership(self)`),
            // fall through so the @takes / R10 checks below get a
            // chance.  The arena_kill emitted above is a no-op at
            // transfer time when the receiver's origin isn't .arena.
            const hint = self.locals.items[@intFromEnum(recv_local)].init_hint;
            if (hint == .arena_local or hint == .arena_allocator) {
                return;
            }
        }

        if (anyPatternMatches(text, self.config.heap_free_patterns)) {
            // `<recv>.destroy(<allocator>)` — struct-method shape
            // where the method frees the receiver and takes the
            // allocator as an arg.  Inverse of `allocator.destroy(p)`.
            // Must check before the standard `.destroy(p)` path so we
            // don't misinterpret the allocator-arg as the freed thing.
            if (self.destroyReceiverFreed(call_node)) |target| {
                switch (target) {
                    .local => |freed| {
                        try self.appendStmt(cur.*, .{
                            .kind = .{ .heap_free = .{ .freed_local = freed, .fallback_hid = blk_h: { const h: abstract_state.HeapId = @enumFromInt(self.next_heap); self.next_heap += 1; break :blk_h h; } } },
                            .pos = self.posOf(call_node),
                            .end_pos = self.endPosOf(call_node),
                        });
                    },
                    .field => |fref| {
                        try self.appendStmt(cur.*, .{
                            .kind = .{ .field_heap_free = .{ .parent = fref.parent, .name = fref.name, .fallback_hid = blk_hid: { const h: abstract_state.HeapId = @enumFromInt(self.next_heap); self.next_heap += 1; break :blk_hid h; } } },
                            .pos = self.posOf(call_node),
                            .end_pos = self.endPosOf(call_node),
                        });
                    },
                }
                return;
            }
            if (self.heapFreedLocal(call_node)) |freed| {
                try self.appendStmt(cur.*, .{
                    .kind = .{ .heap_free = .{ .freed_local = freed, .fallback_hid = blk_h: { const h: abstract_state.HeapId = @enumFromInt(self.next_heap); self.next_heap += 1; break :blk_h h; } } },
                    .pos = self.posOf(call_node),
                    .end_pos = self.endPosOf(call_node),
                });
                return;
            }
            // `g.free(obj.field)` — field-level free.
            if (self.heapFreedField(call_node)) |fref| {
                try self.appendStmt(cur.*, .{
                    .kind = .{ .field_heap_free = .{ .parent = fref.parent, .name = fref.name, .fallback_hid = blk_hid: { const h: abstract_state.HeapId = @enumFromInt(self.next_heap); self.next_heap += 1; break :blk_hid h; } } },
                    .pos = self.posOf(call_node),
                    .end_pos = self.endPosOf(call_node),
                });
                return;
            }
            try self.appendStmt(cur.*, .{
                .kind = .{ .lowering_gap = .{ .note = "free-untracked-arg" } },
                .pos = self.posOf(call_node),
                .end_pos = self.endPosOf(call_node),
            });
            return;
        }

        // `@takes ownership(p)` — annotated free-wrapper.  Look up
        // the callee in the same-file DB; if it carries the
        // annotation, treat this call as a heap_free for the matched
        // arg before falling through to the untracked-call path.
        if (self.takesOwnershipFreedLocal(call_node)) |freed| {
            try self.appendStmt(cur.*, .{
                .kind = .{ .heap_free = .{ .freed_local = freed, .fallback_hid = blk_h: { const h: abstract_state.HeapId = @enumFromInt(self.next_heap); self.next_heap += 1; break :blk_h h; } } },
                .pos = self.posOf(call_node),
                .end_pos = self.endPosOf(call_node),
            });
            return;
        }
        // Same but for `<local>.<field>.method(...)` where method has
        // @takes ownership(0) (R9 inference: callee frees its receiver).
        // The freed thing is the FIELD of the caller's local.  Without
        // this, inter-procedural UAF through struct fields (PR #30176
        // class) is invisible: takesOwnershipFreedLocal returns null
        // because the receiver is a field_access, not a bare ident.
        if (self.takesOwnershipFreedField(call_node)) |fref| {
            try self.appendStmt(cur.*, .{
                .kind = .{ .field_heap_free = .{ .parent = fref.parent, .name = fref.name, .fallback_hid = blk_hid: { const h: abstract_state.HeapId = @enumFromInt(self.next_heap); self.next_heap += 1; break :blk_hid h; } } },
                .pos = self.posOf(call_node),
                .end_pos = self.endPosOf(call_node),
            });
            return;
        }
        // Callee's `may_free_fields` (R10 field-chain inference) —
        // each entry says "the call frees param[N]'s field F".
        // Resolve each to the caller-side local and emit a
        // `.field_heap_free`.  Catches the wrapper-method-frees-
        // field pattern, single or multiple fields, receiver or
        // non-receiver params.
        {
            var emissions: std.ArrayListUnmanaged(CalleeFieldFree) = .empty;
            defer emissions.deinit(self.gpa);
            try self.collectCalleeFieldFrees(call_node, self.gpa, &emissions);
            if (emissions.items.len > 0) {
                for (emissions.items) |em| {
                    try self.appendStmt(cur.*, .{
                        .kind = .{ .field_heap_free = .{ .parent = em.parent, .name = em.field, .fallback_hid = blk_hid: { const h: abstract_state.HeapId = @enumFromInt(self.next_heap); self.next_heap += 1; break :blk_hid h; } } },
                        .pos = self.posOf(call_node),
                        .end_pos = self.endPosOf(call_node),
                    });
                }
                return;
            }
        }

        // Untracked call at stmt position — emit uses for everything
        // it references so UAF on call args still fires before the
        // conservative gap erases tracked origins.
        try self.emitUsesInExpr(call_node, cur.*, null);
        try self.appendStmt(cur.*, .{
            .kind = .{ .lowering_gap = .{ .note = "call-untracked" } },
            .pos = self.posOf(call_node),
            .end_pos = self.endPosOf(call_node),
        });

        // If the callee is annotated/inferred `noreturn`, the call
        // diverges — terminate this block (matches the treatment of
        // `unreachable` / `@panic`).
        if (self.calleeIsNoreturn(call_node)) {
            cur.* = try self.newBlock();
        }
    }

    /// True iff the call's callee resolves to a fn whose DB entry
    /// carries is_noreturn=true, OR the call's source text matches
    /// a known-stdlib noreturn pattern (`std.process.exit`,
    /// `std.os.abort`, `std.posix.exit`, etc.).  The stdlib list
    /// avoids needing zbc to parse std itself — these signatures
    /// don't change.
    fn calleeIsNoreturn(self: *Builder, call_node: Ast.Node.Index) bool {
        const tree = self.tree;
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return false;
        const callee = call_full.ast.fn_expr;
        const method_tok = switch (tree.nodeTag(callee)) {
            .identifier => tree.nodeMainToken(callee),
            .field_access => tree.nodeData(callee).node_and_token[1],
            else => return false,
        };
        const raw_name = tree.tokenSlice(method_tok);
        const name = if (tree.nodeTag(callee) == .identifier)
            self.resolveBoundCallee(raw_name)
        else
            raw_name;
        if (self.db) |db| {
            if (db.lookup(name)) |entry| if (entry.is_noreturn) return true;
        }
        if (tree.nodeTag(callee) == .field_access) {
            const recv = tree.nodeData(callee).node_and_token[0];
            if (self.lookupRemoteEntry(recv, name)) |entry| if (entry.is_noreturn) return true;
        }
        // Aliased noreturn local: `const exit = std.process.exit;`
        // then `exit(1)`.  Bare-identifier callee referencing a
        // local whose init was a known noreturn chain.
        if (tree.nodeTag(callee) == .identifier) {
            if (self.name_to_local.get(name)) |local| {
                if (self.locals.items[@intFromEnum(local)].init_hint == .noreturn_alias) {
                    return true;
                }
            }
        }

        // Known-stdlib noreturn callees.  Match against the leading
        // tokens of the callee chain (not the full call text) so an
        // arg shape like `(exitcode)` doesn't pull patterns from
        // arbitrary user text into the match window.
        const first = tree.firstToken(call_node);
        const callee_last = tree.lastToken(callee);
        const start = tree.tokens.items(.start)[first];
        const end_tok_start = tree.tokens.items(.start)[callee_last];
        const end_tok_len = tree.tokenSlice(callee_last).len;
        const callee_text = tree.source[start .. end_tok_start + end_tok_len];
        for (known_noreturn_chains) |pat| {
            if (std.mem.endsWith(u8, callee_text, pat)) return true;
        }
        return false;
    }

    /// Cross-file FnEntry lookup — shared by callers that need
    /// multiple fields off the remote entry.
    fn lookupRemoteEntry(
        self: *Builder,
        recv_node: Ast.Node.Index,
        method_name: []const u8,
    ) ?annotations.FnEntry {
        const remote = self.remote orelse return null;
        const tree = self.tree;
        if (tree.nodeTag(recv_node) != .identifier) return null;
        const recv_name = tree.tokenSlice(tree.nodeMainToken(recv_node));
        const imap_entry = remote.imap.lookup(recv_name) orelse return null;
        const remote_file = (remote.cache.loadOrLookup(remote.base_dir, imap_entry.path) catch return null) orelse return null;
        return remote_file.db.lookup(method_name);
    }

    /// If the callee has `@takes ownership(p)`, return the LocalId
    /// of the actual arg that maps to p.  Consults the same-file
    /// annotation DB AND (when remote context is available) the
    /// imported file's DB for cross-file wrappers.  Null on miss.
    fn takesOwnershipFreedLocal(self: *Builder, call_node: Ast.Node.Index) ?LocalId {
        const tree = self.tree;
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return null;
        const callee = call_full.ast.fn_expr;

        const method_tok = switch (tree.nodeTag(callee)) {
            .identifier => tree.nodeMainToken(callee),
            .field_access => tree.nodeData(callee).node_and_token[1],
            else => return null,
        };
        const raw_callee_name = tree.tokenSlice(method_tok);
        const callee_name = if (tree.nodeTag(callee) == .identifier)
            self.resolveBoundCallee(raw_callee_name)
        else
            raw_callee_name;
        const receiver_is_arg0 = tree.nodeTag(callee) == .field_access;
        const recv_node: ?Ast.Node.Index = if (receiver_is_arg0)
            tree.nodeData(callee).node_and_token[0]
        else
            null;
        // Receiver's type name — used to disambiguate methods that
        // share a name across container types.  Null when the recv
        // isn't a known local with type info, in which case the DB
        // falls back to bare-name lookup.
        const recv_ty: ?[]const u8 = if (recv_node) |rn|
            self.receiverTypeOfNode(rn)
        else
            null;

        // Look up @takes annotation.  Try same-file first; then
        // cross-file by recv's type (when the type is defined in an
        // imported file); then the remote-namespace path (for
        // `lib.method(...)` where recv IS the namespace).
        const takes = blk: {
            if (self.db) |db| {
                if (db.lookupTyped(recv_ty, callee_name)) |entry| {
                    if (entry.takes) |t| break :blk t;
                }
            }
            if (recv_ty) |ty| {
                if (self.lookupCrossFileMethod(ty, callee_name)) |entry| {
                    if (entry.takes) |t| break :blk t;
                }
            }
            if (receiver_is_arg0) {
                if (self.lookupRemoteTakes(recv_node.?, callee_name)) |t| break :blk t;
            }
            return null;
        };

        const target_idx = switch (takes) {
            .ownership => |i| i,
        };

        // For cross-file namespace calls (`lib.dispose(g, buf)`), the
        // receiver IS the imported namespace — not part of the
        // callee's logical arg list.  ast.params already holds the
        // full explicit-arg list; don't subtract for the namespace.
        const effective_recv_is_arg0 = receiver_is_arg0 and !self.calleeIsImportedNamespace(recv_node.?);

        const candidate = if (effective_recv_is_arg0 and target_idx == 0)
            recv_node.?
        else blk: {
            const explicit_idx = if (effective_recv_is_arg0) target_idx - 1 else target_idx;
            if (explicit_idx >= call_full.ast.params.len) return null;
            break :blk call_full.ast.params[explicit_idx];
        };

        if (tree.nodeTag(candidate) != .identifier) return null;
        const name = tree.tokenSlice(tree.nodeMainToken(candidate));
        return self.name_to_local.get(name);
    }

    /// Companion to `takesOwnershipFreedLocal`: when the call is
    /// `<local>.<field>.method(...)` and method has @takes
    /// ownership(0) (receiver-freeing — R8b inferred or annotated),
    /// the freed entity is the FIELD of caller's local.
    /// Returns the (local, field-name) pair for emission as
    /// .field_heap_free.
    fn takesOwnershipFreedField(self: *Builder, call_node: Ast.Node.Index) ?FieldRef {
        const tree = self.tree;
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return null;
        const callee = call_full.ast.fn_expr;
        if (tree.nodeTag(callee) != .field_access) return null;
        const fa = tree.nodeData(callee).node_and_token;
        const recv = fa[0];
        // Receiver must be `<local>.<field>` exactly (one level of
        // field access).  Deeper chains (`a.b.c.method()`) are out of
        // scope for now — they need full field-aliasing.
        if (tree.nodeTag(recv) != .field_access) return null;
        const recv_fa = tree.nodeData(recv).node_and_token;
        const recv_recv = recv_fa[0];
        if (tree.nodeTag(recv_recv) != .identifier) return null;
        const recv_name = tree.tokenSlice(tree.nodeMainToken(recv_recv));
        const parent = self.name_to_local.get(recv_name) orelse return null;
        const field_name = tree.tokenSlice(recv_fa[1]);
        const method_name = tree.tokenSlice(fa[1]);

        // The receiver of the method call is the FIELD (`parent.field`).
        // Resolve its declared type via the parent local's type +
        // field name → Db.fieldType.  This scopes `<local>.<field>
        // .<method>()` lookups to the field's exact type instead of
        // falling back to bare-name (which would inherit a sibling
        // overload's annotation across types).
        const recv_ty: ?[]const u8 = blk: {
            const parent_ty = self.locals.items[@intFromEnum(parent)].type_name orelse break :blk null;
            const db = self.db orelse break :blk null;
            break :blk db.fieldType(parent_ty, field_name);
        };

        // Resolve method's @takes via same-file or cross-file DB.
        const takes = blk: {
            if (self.db) |db| {
                if (db.lookupTyped(recv_ty, method_name)) |entry| {
                    if (entry.takes) |t| break :blk t;
                }
            }
            // Cross-file: the field's type may be defined in an
            // imported file (e.g. `r.foo: *RemoteType; r.foo.method()`
            // where RemoteType lives in lib.zig).
            if (recv_ty) |ty| {
                if (self.lookupCrossFileMethod(ty, method_name)) |entry| {
                    if (entry.takes) |t| break :blk t;
                }
            }
            return null;
        };
        switch (takes) {
            .ownership => |idx| if (idx != 0) return null,
        }
        return .{ .parent = parent, .name = field_name };
    }

    /// Best-effort type name for a node used as a method-call
    /// receiver.  Looks up the node's identifier in name_to_local to
    /// get a known local's declared type.  Returns null when the
    /// node isn't a tracked local or doesn't have a type annotation
    /// — callers fall back to bare-name lookup.
    fn receiverTypeOfNode(self: *Builder, node: Ast.Node.Index) ?[]const u8 {
        const tree = self.tree;
        if (tree.nodeTag(node) != .identifier) return null;
        const name = tree.tokenSlice(tree.nodeMainToken(node));
        const lid = self.name_to_local.get(name) orelse return null;
        return self.locals.items[@intFromEnum(lid)].type_name;
    }

    /// A single (parent_local, field) emission triggered by a
    /// callee's `may_free_fields` entry at the call site.
    /// `lowerCallStmt`/`applyTopLevelCallEffects` emit one
    /// `.field_heap_free` per slot.
    const CalleeFieldFree = struct {
        parent: LocalId,
        field: []const u8,
    };

    /// Walk the callee's `may_free_fields` list, resolve each
    /// `{param, field}` to the corresponding caller-side arg local,
    /// and call `cb` with the resolved `(parent, field)` pair.
    /// Entries whose param maps to an unresolvable arg (non-ident,
    /// out of bounds) are silently skipped.
    ///
    /// Handles method-call form (`recv.method(a, b)` — param 0 =
    /// recv, param N = call's args[N-1]) and bare call form
    /// (`fn(a, b, c)` — param N = call's args[N]).  Imported-
    /// namespace prefixes (`bun.method(p)`) don't consume a param
    /// slot — `bun` isn't a logical argument.
    fn collectCalleeFieldFrees(
        self: *Builder,
        call_node: Ast.Node.Index,
        gpa: std.mem.Allocator,
        out: *std.ArrayListUnmanaged(CalleeFieldFree),
    ) !void {
        const tree = self.tree;
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return;
        const callee = call_full.ast.fn_expr;

        const method_tok = switch (tree.nodeTag(callee)) {
            .identifier => tree.nodeMainToken(callee),
            .field_access => tree.nodeData(callee).node_and_token[1],
            else => return,
        };
        const raw_callee_name = tree.tokenSlice(method_tok);
        const callee_name = if (tree.nodeTag(callee) == .identifier)
            self.resolveBoundCallee(raw_callee_name)
        else
            raw_callee_name;
        const receiver_is_arg0 = tree.nodeTag(callee) == .field_access;
        const recv_node: ?Ast.Node.Index = if (receiver_is_arg0)
            tree.nodeData(callee).node_and_token[0]
        else
            null;
        const recv_ty: ?[]const u8 = if (recv_node) |rn|
            self.receiverTypeOfNode(rn)
        else
            null;

        // Resolve callee entry: typed local → cross-file → null.
        const entry: annotations.FnEntry = blk: {
            if (self.db) |db| {
                if (db.lookupTyped(recv_ty, callee_name)) |e| break :blk e;
            }
            if (recv_ty) |ty| {
                if (self.lookupCrossFileMethod(ty, callee_name)) |e| break :blk e;
            }
            return;
        };
        if (entry.may_free_fields.len == 0) return;

        // For method-call shape, param 0 is the receiver; subsequent
        // params come from explicit args.  Imported namespaces
        // (`bun.method(p)`) are NOT a logical arg — strip from the
        // receiver-is-arg0 calculation so param indices map to
        // explicit args directly.
        const effective_recv_is_arg0 = receiver_is_arg0 and recv_node != null and
            !self.calleeIsImportedNamespace(recv_node.?);

        for (entry.may_free_fields) |ff| {
            // Map the callee's param index to the caller's arg node.
            const arg_node: Ast.Node.Index = if (effective_recv_is_arg0 and ff.param == 0)
                recv_node.?
            else blk: {
                const explicit_idx = if (effective_recv_is_arg0) ff.param - 1 else ff.param;
                if (explicit_idx >= call_full.ast.params.len) continue;
                break :blk call_full.ast.params[explicit_idx];
            };
            // The arg local must be a bare identifier known to the
            // caller — that's the only shape we can rebind a field
            // origin on.
            if (tree.nodeTag(arg_node) != .identifier) continue;
            const arg_name = tree.tokenSlice(tree.nodeMainToken(arg_node));
            const parent = self.name_to_local.get(arg_name) orelse continue;
            try out.append(gpa, .{ .parent = parent, .field = ff.field });
        }
    }

    /// Cross-file method lookup by (containing_type, method_name).
    /// Walks every imap entry, loads the file, checks if that file
    /// declares `type_name` (via Db.hasType), and if so does the
    /// typed lookup there.  Returns the first matching entry.
    ///
    /// Used when a local has a type name that isn't defined in the
    /// caller's file — e.g. `var loader: *lib.HTMLRewriterLoader =
    /// ...; loader.finalize();` where HTMLRewriterLoader lives in
    /// lib.zig.  The local db can't find HTMLRewriterLoader; this
    /// helper walks imports and tries each remote db.
    ///
    /// Ambiguity: if MULTIPLE imported files define a type with the
    /// same name, only the FIRST match is returned.  Bun's codebase
    /// shouldn't hit this in practice (struct names are unique
    /// per-file by convention), but the alternative — return null
    /// on multi-match — would silently drop catches.  First-match
    /// is the pragmatic choice.
    fn lookupCrossFileMethod(
        self: *Builder,
        type_name: []const u8,
        method_name: []const u8,
    ) ?annotations.FnEntry {
        const remote = self.remote orelse return null;
        var it = remote.imap.entries.iterator();
        while (it.next()) |kv| {
            const remote_file = (remote.cache.loadOrLookup(remote.base_dir, kv.value_ptr.path) catch continue) orelse continue;
            if (!remote_file.db.hasType(type_name)) continue;
            if (remote_file.db.lookupTyped(type_name, method_name)) |e| return e;
        }
        return null;
    }

    /// Cross-file `@takes` lookup — see lookupRemoteMethod for the
    /// resolution mechanics.
    fn lookupRemoteTakes(
        self: *Builder,
        recv_node: Ast.Node.Index,
        method_name: []const u8,
    ) ?annotations.TakesAnnotation {
        const remote = self.remote orelse return null;
        const tree = self.tree;
        if (tree.nodeTag(recv_node) != .identifier) return null;
        const recv_name = tree.tokenSlice(tree.nodeMainToken(recv_node));
        const imap_entry = remote.imap.lookup(recv_name) orelse return null;
        const remote_file = (remote.cache.loadOrLookup(remote.base_dir, imap_entry.path) catch return null) orelse return null;
        const entry = remote_file.db.lookup(method_name) orelse return null;
        return entry.takes;
    }

    /// True iff `node` is a bare identifier that resolves to an
    /// imported namespace in our imap (e.g. `lib` in `lib.foo(...)`).
    /// Used to disambiguate method-style calls from namespace calls.
    fn calleeIsImportedNamespace(self: *Builder, node: Ast.Node.Index) bool {
        const remote = self.remote orelse return false;
        const tree = self.tree;
        if (tree.nodeTag(node) != .identifier) return false;
        const name = tree.tokenSlice(tree.nodeMainToken(node));
        return remote.imap.lookup(name) != null;
    }

    /// For `<allocator>.free(p)` / `<allocator>.destroy(p)`, return the
    /// LocalId of `p` if it's a known local.  Null on any other shape.
    fn heapFreedLocal(self: *Builder, call_node: Ast.Node.Index) ?LocalId {
        const tree = self.tree;
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return null;
        if (call_full.ast.params.len == 0) return null;
        const arg = call_full.ast.params[0];
        if (tree.nodeTag(arg) != .identifier) return null;
        const name = tree.tokenSlice(tree.nodeMainToken(arg));
        return self.name_to_local.get(name);
    }

    /// For `<allocator>.free(obj.field)` shape, return the FieldRef.
    fn heapFreedField(self: *Builder, call_node: Ast.Node.Index) ?FieldRef {
        const tree = self.tree;
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return null;
        if (call_full.ast.params.len == 0) return null;
        const arg = call_full.ast.params[0];
        return self.fieldLhsFor(arg);
    }

    /// True iff `name` is conventionally an allocator binding:
    /// `allocator`, `gpa`, `alloc`, or a suffixed form
    /// (`child_allocator`, `arena_allocator`, etc.).
    fn looksLikeAllocatorName(name: []const u8) bool {
        if (std.mem.eql(u8, name, "allocator")) return true;
        if (std.mem.eql(u8, name, "alloc")) return true;
        if (std.mem.eql(u8, name, "gpa")) return true;
        if (std.mem.endsWith(u8, name, "_allocator")) return true;
        if (std.mem.endsWith(u8, name, "_gpa")) return true;
        return false;
    }

    /// True iff `node` is an expression whose surface name suggests an
    /// allocator: bare identifier with an allocator-looking name, or a
    /// field access whose terminal field is allocator-looking.
    fn exprLooksLikeAllocator(self: *Builder, node: Ast.Node.Index) bool {
        const tree = self.tree;
        switch (tree.nodeTag(node)) {
            .identifier => {
                const name = tree.tokenSlice(tree.nodeMainToken(node));
                return looksLikeAllocatorName(name);
            },
            .field_access => {
                const fa = tree.nodeData(node).node_and_token;
                const field = tree.tokenSlice(fa[1]);
                return looksLikeAllocatorName(field);
            },
            else => return false,
        }
    }

    /// `<recv>.destroy(<allocator_arg>)` shape — return what's freed.
    /// The struct-method `destroy` convention takes an allocator and
    /// frees the receiver, the inverse of `allocator.destroy(p)`.
    /// Distinguished from `allocator.destroy(p)` by the first arg
    /// looking like an allocator (and the method being literally
    /// `destroy`, not `free`).
    const DestroyTarget = union(enum) {
        local: LocalId,
        field: FieldRef,
    };
    fn destroyReceiverFreed(self: *Builder, call_node: Ast.Node.Index) ?DestroyTarget {
        const tree = self.tree;
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return null;
        const callee = call_full.ast.fn_expr;
        if (tree.nodeTag(callee) != .field_access) return null;
        const fa = tree.nodeData(callee).node_and_token;
        const method = tree.tokenSlice(fa[1]);
        if (!std.mem.eql(u8, method, "destroy")) return null;
        if (call_full.ast.params.len == 0) return null;
        const arg = call_full.ast.params[0];
        if (!self.exprLooksLikeAllocator(arg)) return null;
        const recv = fa[0];
        // Receiver is the freed thing.  Bare ident → local; field
        // access shape `parent.field` → FieldRef.
        switch (tree.nodeTag(recv)) {
            .identifier => {
                const name = tree.tokenSlice(tree.nodeMainToken(recv));
                // Skip allocator-named receivers (`allocator.destroy`)
                // — those are the canonical Allocator.destroy shape,
                // and our pattern matched only because the *arg* also
                // looked allocator-ish (rare, but possible).
                if (looksLikeAllocatorName(name)) return null;
                // Skip imported namespaces (`bun.destroy(...)`).
                if (self.calleeIsImportedNamespace(recv)) return null;
                const id = self.name_to_local.get(name) orelse return null;
                return .{ .local = id };
            },
            .field_access => {
                const fref = self.fieldLhsFor(recv) orelse return null;
                return .{ .field = fref };
            },
            else => return null,
        }
    }


    fn classifyExpr(self: *Builder, expr_node: Ast.Node.Index) ExprKind {
        const tree = self.tree;
        const tag = tree.nodeTag(expr_node);

        // `try expr` — unwrap and classify the inner expression.  The
        // error-exit edge isn't modeled yet (phase 9); for success-path
        // analysis the wrapped value has the same origin as the inner
        // call's return.
        if (tag == .@"try") {
            return self.classifyExpr(tree.nodeData(expr_node).node);
        }

        // `lhs catch rhs` — the success-path value has the lhs's
        // origin (e.g. `gpa.alloc(...) catch return &.{}` produces a
        // heap allocation on success).  The error path is modeled
        // separately via emitCatchFork at statement level; here we
        // just unwrap to lhs so the origin propagates into the
        // declaring local instead of collapsing to .unknown.
        if (tag == .@"catch") {
            return self.classifyExpr(tree.nodeData(expr_node).node_and_node[0]);
        }

        // `ArenaAllocator.init(...)` → .arena_init
        // Match arena_init patterns against the CALLEE text only —
        // the function name being called — not the full call
        // expression.  Without this, a wrapping call whose args
        // happen to mention "ArenaAllocator.init" (e.g. `bun.new(T,
        // .{ .arena = ArenaAllocator.init(alloc) })`) would
        // accidentally classify as arena_init, then `return this`
        // would flag a bogus arena-escape.
        const first = tree.firstToken(expr_node);
        const last = tree.lastToken(expr_node);
        const start = tree.tokens.items(.start)[first];
        const last_start = tree.tokens.items(.start)[last];
        const last_len = tree.tokenSlice(last).len;
        const end: usize = last_start + last_len;
        const text = tree.source[start..end];

        const callee_text = self.calleeText(expr_node) orelse text;
        if (anyPatternMatches(callee_text, self.config.arena_init_patterns)) {
            const aid: abstract_state.ArenaId = @enumFromInt(self.next_arena);
            self.next_arena += 1;
            return .{ .arena_init = .{ .id = aid } };
        }
        // Heap-allocated arena: `gpa.create(ArenaAllocator)` returns a
        // pointer to a fresh arena.  The pointer itself is heap, but
        // the arena identity is what matters for UAK tracking — its
        // .deinit() kills the underlying bump memory regardless of
        // where the descriptor lives.  Treat as arena_init so
        // arena_kill propagation works.  Detected by combining
        // heap_alloc pattern match with "ArenaAllocator" in the call
        // text (the type passed to `.create`).
        // Heap-alloc / arena-via-create patterns: only fire when the
        // expression itself is a call.  Without this gate, a struct
        // literal whose field initializer is `alloc.alloc(...)` would
        // text-match the heap pattern, accidentally tagging the whole
        // literal as a fresh heap allocation and binding the parent
        // local's origin to the matched cell — breaking subsequent
        // @takes-ownership / field-use checks on the local.
        const is_call_node = switch (tree.nodeTag(expr_node)) {
            .call, .call_one, .call_comma, .call_one_comma => true,
            else => false,
        };
        if (is_call_node) {
            if (anyPatternMatches(text, self.config.heap_alloc_patterns) and
                std.mem.indexOf(u8, text, "ArenaAllocator") != null and
                std.mem.indexOf(u8, text, ".create(") != null)
            {
                const aid: abstract_state.ArenaId = @enumFromInt(self.next_arena);
                self.next_arena += 1;
                return .{ .arena_init = .{ .id = aid, .is_heap_allocated = true } };
            }
            if (anyPatternMatches(text, self.config.heap_alloc_patterns)) {
                // Allocator-provenance check: if the call's immediate
                // receiver is a local known to be an arena_allocator
                // (or the arena itself, for direct
                // `arena.allocator().alloc()` is handled via
                // .allocator() classification below), the result is
                // arena-bound memory, NOT a fresh heap allocation.
                // Catches the canonical pattern
                //   const a = arena.allocator(); buf = a.alloc(...);
                //   arena.deinit(); use(buf);  // UAK
                if (self.arenaBoundReceiverOfCall(expr_node)) |arena_src| {
                    return .{ .copy_of = arena_src };
                }
                const hid: abstract_state.HeapId = @enumFromInt(self.next_heap);
                self.next_heap += 1;
                return .{ .heap_alloc = hid };
            }
        }

        // `<arena_local>.allocator()` — return an Allocator value
        // bound to the arena's lifetime.  Returning .copy_of(arena)
        // gives the receiving local the arena's origin; lowerVarDecl
        // additionally sets init_hint = .arena_allocator so .alloc
        // calls through the alias also produce arena memory.
        if (std.mem.indexOf(u8, text, ".allocator(") != null) {
            if (self.arenaLocalDotAllocatorReceiver(expr_node)) |arena_local| {
                return .{ .copy_of = arena_local };
            }
        }

        // Constructor-style call taking an arena-bound allocator as
        // its first arg: `Type.init(arena_alloc, ...)`,
        // `Type.create(arena_alloc, ...)`, etc.  The returned value
        // very likely embeds storage from that allocator, so its
        // lifetime is bound to the arena.  Heuristic R7-lite for
        // user-defined types we have no annotation for — without it,
        // canonical patterns like
        //   var log = Log.init(arena.allocator());
        //   arena.deinit();
        //   log.toJS();   // UAK — log's internals were arena-backed
        // would never fire.  Trigger only on conventional constructor
        // method names so we don't propagate arena origin to e.g.
        // `globalThis.throwValue(alloc, ...)` which doesn't embed.
        if (self.constructorWithArenaArg(expr_node)) |arena_src| {
            return .{ .copy_of = arena_src };
        }

        // `obj.field` where obj is a known local → .field_copy_of.
        // Lets free / use of a field be tracked against its own
        // origin separately from the parent local.
        //
        // EXCEPTION: `.ptr` on a slice is the raw data pointer of the
        // slice descriptor itself — it points into the SAME allocation
        // as the slice.  Inherit the parent's origin (.copy_of) so
        // `@ptrCast(raw.ptr)` correctly carries raw's heap/arena.
        if (tag == .field_access) {
            const fa = tree.nodeData(expr_node).node_and_token;
            const recv = fa[0];
            const field_tok = fa[1];
            if (tree.nodeTag(recv) == .identifier) {
                const recv_name = tree.tokenSlice(tree.nodeMainToken(recv));
                if (self.name_to_local.get(recv_name)) |id| {
                    const fname = tree.tokenSlice(field_tok);
                    if (std.mem.eql(u8, fname, "ptr")) {
                        return .{ .copy_of = id };
                    }
                    // `/// @borrowed` field annotation: the field's
                    // storage is owned by the containing struct, so a
                    // read of `local.field` yields a borrow tied to
                    // `local`'s lifetime.  Surface as .stack_ref(local)
                    // so it composes with the stack-owner liveness
                    // check at use sites — `owner.die()` then
                    // invalidates the borrow.
                    if (self.db) |db| {
                        const info = self.locals.items[@intFromEnum(id)];
                        if (info.type_name) |ty| if (db.isBorrowedField(ty, fname)) {
                            if (!info.is_pointer) return .{ .stack_ref = id };
                        };
                    }
                    return .{ .field_copy_of = .{ .parent = id, .name = fname } };
                }
            }
            // Deep chain (`<local>.<f1>.<f2>...`): walk down via
            // `fieldLhsFor` to find the root local and the
            // dotted-path it builds, then look up `(root_type,
            // dotted_path)` in `borrowed_fields`.  Closes the gap
            // where nested-literal inference marks dotted paths
            // borrowed but the single-level classifier above only
            // catches `<local>.<field>`.
            //
            // Two-tier lookup: first try the literal dotted-path
            // (set by nested-literal inference) for a direct match,
            // then fall through to a per-step walk via
            // `isBorrowedDeepChain` which threads through
            // `db.field_types`, stops at any pointer-typed
            // intermediate field, and reports any `@borrowed`
            // step along the way.  The per-step path catches the
            // explicit-leaf-annotation case
            // (`Inner.buf @borrowed`, read via `o.outer.buf`).
            if (self.db) |db| {
                if (self.fieldLhsFor(expr_node)) |fref| {
                    const info = self.locals.items[@intFromEnum(fref.parent)];
                    if (info.type_name) |ty| {
                        const borrowed = db.isBorrowedField(ty, fref.name) or
                            db.isBorrowedDeepChain(ty, fref.name);
                        if (borrowed and !info.is_pointer) return .{ .stack_ref = fref.parent };
                    }
                }
            }
        }

        // Identifier reference → .undef / .copy_of(local) if known
        if (tag == .identifier) {
            const name = tree.tokenSlice(tree.nodeMainToken(expr_node));
            if (std.mem.eql(u8, name, "undefined")) return .undef;
            if (self.name_to_local.get(name)) |id| {
                return .{ .copy_of = id };
            }
        }

        // `&<local>` — address-of of a known local.  Produces a
        // pointer bound to that local's stack frame.  Also accept
        // `&<local>.<field>(.<f2>...)` — a borrow into the local's
        // storage; same lifetime semantics, since taking the address
        // of a field is taking a pointer into the parent.
        if (tag == .address_of) {
            const inner = tree.nodeData(expr_node).node;
            if (tree.nodeTag(inner) == .identifier) {
                const name = tree.tokenSlice(tree.nodeMainToken(inner));
                if (self.name_to_local.get(name)) |id| {
                    return .{ .stack_ref = id };
                }
            }
            if (tree.nodeTag(inner) == .field_access) {
                if (self.fieldLhsFor(inner)) |fref| {
                    // Pointer-typed parent: the pointee lives in the
                    // caller, not this fn's stack frame.  `&self.field`
                    // where `self: *Self` is a borrow from caller-owned
                    // storage — not a stack escape candidate.
                    if (self.locals.items[@intFromEnum(fref.parent)].is_pointer) {
                        return .unknown;
                    }
                    return .{ .stack_ref = fref.parent };
                }
            }
        }

        // `<local>[..]` / `<local>[a..b]` / `<local>[a..b :s]` —
        // slicing a `[N]T` local produces a fat pointer into the
        // local's stack storage.  For escape purposes that's
        // identical to &local: returning the slice past the frame
        // is UB.  Only fires when the sliced local was declared
        // with an array type — slicing a local that already holds
        // a slice or pointer just makes another view of caller-
        // owned storage.
        const slicee_opt: ?Ast.Node.Index = switch (tag) {
            .slice_open => tree.nodeData(expr_node).node_and_node[0],
            .slice, .slice_sentinel => tree.nodeData(expr_node).node_and_extra[0],
            else => null,
        };
        // Labeled-block expression (`blk: { ... break :blk X; }`):
        // body was already lowered by maybeLowerLabeledBlockExpr in
        // the caller.  Classify the break value here so the .ret /
        // assign sees the right origin.  If exactly one `break :blk`
        // with a value exists, use that; multiple distinct break
        // values fall through to .unknown.
        switch (tag) {
            .block, .block_semicolon, .block_two, .block_two_semicolon => {
                if (self.blockLabelToken(expr_node)) |lt| {
                    if (self.singleLabeledBreakValue(expr_node, lt)) |v| {
                        return self.classifyExpr(v);
                    }
                }
            },
            else => {},
        }

        if (slicee_opt) |slicee| {
            if (tree.nodeTag(slicee) == .identifier) {
                const name = tree.tokenSlice(tree.nodeMainToken(slicee));
                if (self.name_to_local.get(name)) |id| {
                    const info = self.locals.items[@intFromEnum(id)];
                    if (info.is_array) {
                        return .{ .stack_ref = id };
                    }
                    // Slice of a heap/arena-bearing local — the
                    // sub-slice aliases the same allocation, so
                    // propagate the local's origin via .copy_of.
                    // `const view = buf[0..n]; free(buf); return view;`
                    // then correctly fires UAF.
                    if (info.init_hint == .heap_local or info.init_hint == .arena_local) {
                        return .{ .copy_of = id };
                    }
                }
            }
        }

        // Transparent cast builtins: `@ptrCast(x)`, `@bitCast(x)`,
        // `@alignCast(x)`, `@constCast(x)`, `@volatileCast(x)`,
        // `@addrSpaceCast(x)`, `@as(T, x)`, `@fieldParentPtr(name, p)`.
        // Each produces a value that aliases the underlying storage
        // of its source arg — propagate the source's origin so
        // free-then-use through a cast is caught.
        //
        // For ANY OTHER builtin call (`@truncate(...)`, `@intCast(...)`,
        // `@hash(...)` etc.), the result's lifetime is unrelated to
        // its args — return .unknown so the composite-fallback walker
        // doesn't pick up address-of-args buried inside the builtin's
        // arguments as if they were the return value's shape.
        switch (tag) {
            .builtin_call, .builtin_call_two, .builtin_call_comma, .builtin_call_two_comma => {
                if (self.transparentCastSource(expr_node)) |src| {
                    return self.classifyExpr(src);
                }
                return .unknown;
            },
            else => {},
        }

        // Annotated method/function call: `<recv>.<method>(args)` or
        // bare `<fn>(args)`.  Look up the callee in the annotation DB
        // and use its @returns to classify the result.
        const is_call = switch (tag) {
            .call, .call_one, .call_comma, .call_one_comma => true,
            else => false,
        };
        if (is_call) {
            return self.classifyCall(expr_node);
        }

        // Composite escape fallback — only fires for expressions
        // whose TOP-LEVEL shape is a composite literal (struct or
        // array init).  For other shapes (binary ops, catch chains,
        // parens, ifs, etc.) an `&local` token sequence inside is
        // typically a call arg buried in the expression, not part
        // of the return value's shape — firing would produce a
        // flood of false positives like `return (call(&buf)) != 0`.
        const is_composite_literal = switch (tag) {
            .struct_init, .struct_init_comma,
            .struct_init_one, .struct_init_one_comma,
            .struct_init_dot, .struct_init_dot_comma,
            .struct_init_dot_two, .struct_init_dot_two_comma,
            .array_init, .array_init_comma,
            .array_init_one, .array_init_one_comma,
            .array_init_dot, .array_init_dot_comma,
            .array_init_dot_two, .array_init_dot_two_comma,
            => true,
            else => false,
        };
        if (is_composite_literal) {
            if (self.firstAddressedLocal(expr_node)) |id| {
                return .{ .stack_ref = id };
            }
            if (!self.suppress_composite_borrow) {
                if (self.firstResourceMethodBorrow(expr_node)) |id| {
                    return .{ .composite_borrow = id };
                }
            }
        }

        return .unknown;
    }

    /// Walk `expr_node`'s tokens for every borrow shape recognized
    /// by firstAddressedLocal (`&id`, `array_local[`), skipping
    /// `primary_local` (already handled by the surrounding .ret).
    /// Emits one .composite_escape per additional distinct borrow
    /// so multi-borrow composite returns get fully flagged.
    fn emitAdditionalEscapeChecks(
        self: *Builder,
        expr_node: Ast.Node.Index,
        cur: BlockId,
        primary_local: ?LocalId,
    ) !void {
        const tree = self.tree;
        const first = tree.firstToken(expr_node);
        const last = tree.lastToken(expr_node);
        const tags = tree.tokens.items(.tag);
        const pos = self.posOf(expr_node);
        const end_pos = self.endPosOf(expr_node);

        var seen: std.AutoArrayHashMapUnmanaged(LocalId, void) = .empty;
        defer seen.deinit(self.gpa);
        if (primary_local) |p| try seen.put(self.gpa, p, {});

        // Same depth-gate as firstAddressedLocal: only direct field
        // values of the outermost composite literal, not nested
        // inside call args / switch arms / sub-literals.
        var depth: i32 = 0;
        var t: Ast.TokenIndex = first;
        while (t <= last) : (t += 1) {
            switch (tags[t]) {
                .l_brace, .l_paren, .l_bracket => depth += 1,
                .r_brace, .r_paren, .r_bracket => depth -= 1,
                else => {},
            }
            if (depth != 1) continue;
            const id_opt: ?LocalId = blk: {
                if (tags[t] == .ampersand and t + 1 <= last and tags[t + 1] == .identifier) {
                    if (t + 2 <= last) {
                        const next = tags[t + 2];
                        if (next == .period or next == .l_bracket) break :blk null;
                    }
                    const name = tree.tokenSlice(t + 1);
                    break :blk self.name_to_local.get(name);
                }
                if (tags[t] == .identifier and t + 1 <= last and tags[t + 1] == .l_bracket) {
                    if (t > 0 and tags[t - 1] == .period) break :blk null;
                    const name = tree.tokenSlice(t);
                    const local = self.name_to_local.get(name) orelse break :blk null;
                    if (!self.locals.items[@intFromEnum(local)].is_array) break :blk null;
                    break :blk local;
                }
                break :blk null;
            };
            const local = id_opt orelse continue;
            const gop = try seen.getOrPut(self.gpa, local);
            if (gop.found_existing) continue;
            try self.appendStmt(cur, .{
                .kind = .{ .composite_escape = .{ .local = local } },
                .pos = pos,
                .end_pos = end_pos,
            });
        }
    }

    /// Walk `expr_node`'s tokens looking for either:
    ///   `&<ident>`         — address-of a known local, OR
    ///   `<array_local>[`   — slice/index of a known `[N]T` local.
    /// Returns the first such LocalId — caller propagates as
    /// `.stack_ref` so transferRet can flag the escape.
    fn firstAddressedLocal(self: *Builder, expr_node: Ast.Node.Index) ?LocalId {
        const tree = self.tree;
        const first = tree.firstToken(expr_node);
        const last = tree.lastToken(expr_node);
        const tags = tree.tokens.items(.tag);

        // Bracket-depth tracker: only fire at depth == 1 (direct
        // field values of the OUTERMOST struct/array literal).  At
        // depth 0 we'd match expressions outside the literal (we
        // skip that anyway since callers gate on the literal tag).
        // At depth 2+ we're inside nested calls, switch arms,
        // sub-literals — `&local` there is rarely a field value.
        var depth: i32 = 0;
        var t: Ast.TokenIndex = first;
        while (t <= last) : (t += 1) {
            switch (tags[t]) {
                .l_brace, .l_paren, .l_bracket => depth += 1,
                .r_brace, .r_paren, .r_bracket => depth -= 1,
                else => {},
            }
            if (depth != 1) continue;

            // Address-of pattern: `& <ident>` where `<ident>` is the
            // WHOLE address-of operand (not `&local.field` /
            // `&local[i]` — those address memory the local merely
            // points INTO, typically caller-owned).
            if (tags[t] == .ampersand and t + 1 <= last and tags[t + 1] == .identifier) {
                if (t + 2 <= last) {
                    const next = tags[t + 2];
                    if (next == .period or next == .l_bracket) continue;
                }
                const name = tree.tokenSlice(t + 1);
                if (self.name_to_local.get(name)) |local| return local;
                continue;
            }
            // Slice/index of a stack array: `<ident> [`
            if (tags[t] == .identifier and t + 1 <= last and tags[t + 1] == .l_bracket) {
                // Skip if preceded by `.` (struct field access on something).
                if (t > 0 and tags[t - 1] == .period) continue;
                const name = tree.tokenSlice(t);
                const local = self.name_to_local.get(name) orelse continue;
                if (self.locals.items[@intFromEnum(local)].is_array) return local;
            }
        }
        return null;
    }

    /// Walk `expr_node`'s tokens looking for any
    ///   `<local> ( . <id> )* . <method> (`
    /// shape — i.e. a known local at the head, optional field-chain,
    /// then a method call.  Fires when:
    ///   - `local` has an arena/heap init_hint
    ///   - `method`'s annotation (in the same-file DB) is
    ///     `@returns borrowed_from(self)`
    /// Caller propagates as `.composite_borrow` so transferRet fires
    /// escape checks even on value-shape returns.
    fn firstResourceMethodBorrow(self: *Builder, expr_node: Ast.Node.Index) ?LocalId {
        const tree = self.tree;
        const db = self.db orelse return null;
        const first = tree.firstToken(expr_node);
        const last = tree.lastToken(expr_node);
        const tags = tree.tokens.items(.tag);

        var t: Ast.TokenIndex = first;
        while (t + 3 <= last) : (t += 1) {
            if (tags[t] != .identifier) continue;
            // Receiver token must not itself be a field (preceded by `.`).
            if (t > 0 and tags[t - 1] == .period) continue;
            // Must be followed by at least one `.`
            if (tags[t + 1] != .period) continue;

            const recv_name = tree.tokenSlice(t);
            const local = self.name_to_local.get(recv_name) orelse continue;
            const hint = self.locals.items[@intFromEnum(local)].init_hint;
            if (hint == .other) continue;

            // Walk the dot-chain: every step must be `. <id>`.  The
            // last `<id>` before `(` is the method we look up.
            var k: Ast.TokenIndex = t + 1; // current `.`
            var method_tok: Ast.TokenIndex = 0;
            while (k + 1 <= last and tags[k] == .period and tags[k + 1] == .identifier) {
                method_tok = k + 1;
                k += 2;
                if (k > last) break;
                if (tags[k] == .l_paren) break;
                // Otherwise expect another `.` for next chain step.
                if (tags[k] != .period) {
                    method_tok = 0; // not a method-call chain
                    break;
                }
            }
            if (method_tok == 0) continue;
            if (k > last or tags[k] != .l_paren) continue;

            const method_name = tree.tokenSlice(method_tok);
            const entry = db.lookup(method_name) orelse continue;
            if (entry.annotation) |a| switch (a) {
                .borrowed_from => |idx| if (idx == 0) return local,
                else => {},
            };
        }
        return null;
    }

    /// For a call expression `<recv>.method(...)`, if `recv` resolves
    /// to a known local whose init_hint marks it as arena-bound
    /// (.arena_local or .arena_allocator), return that local.
    /// Receiver may itself be a chained field access (`x.y.method()`),
    /// in which case we walk to the head identifier.
    fn arenaBoundReceiverOfCall(self: *Builder, call_node: Ast.Node.Index) ?LocalId {
        const tree = self.tree;
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return null;
        const callee = call_full.ast.fn_expr;
        if (tree.nodeTag(callee) != .field_access) return null;
        const fa = tree.nodeData(callee).node_and_token;
        var cur = fa[0];
        while (true) {
            switch (tree.nodeTag(cur)) {
                .identifier => {
                    const name = tree.tokenSlice(tree.nodeMainToken(cur));
                    const id = self.name_to_local.get(name) orelse return null;
                    const hint = self.locals.items[@intFromEnum(id)].init_hint;
                    if (hint == .arena_local or hint == .arena_allocator) return id;
                    return null;
                },
                .field_access => {
                    cur = tree.nodeData(cur).node_and_token[0];
                },
                // Chained call: `arena.allocator().alloc(...)`.  If
                // the inner call is `<arena_local>.allocator()`,
                // treat the outer call's receiver as arena_local.
                .call, .call_one, .call_comma, .call_one_comma => {
                    if (self.arenaLocalDotAllocatorReceiver(cur)) |arena_local| {
                        return arena_local;
                    }
                    return null;
                },
                else => return null,
            }
        }
    }

    /// Constructor-style call (method `init` / `create` / etc.) on a
    /// type, whose first argument is an arena-bound local.  Treats
    /// the return value as bound to that arena's lifetime — covers
    /// user-defined types like `Log.init(arena.allocator())` where
    /// the constructed value embeds storage from the allocator.
    ///
    /// Triggered only on conventional constructor names so we don't
    /// misclassify ordinary calls that happen to take an allocator
    /// for transient internal use (e.g. `vm.execute(allocator, src)`
    /// which returns a value unrelated to allocator's arena).
    fn constructorWithArenaArg(self: *Builder, call_node: Ast.Node.Index) ?LocalId {
        const tree = self.tree;
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return null;
        const callee = call_full.ast.fn_expr;
        if (tree.nodeTag(callee) != .field_access) return null;
        const fa = tree.nodeData(callee).node_and_token;
        const method = tree.tokenSlice(fa[1]);
        if (!isConstructorName(method)) return null;
        const args = call_full.ast.params;
        if (args.len == 0) return null;
        // Walk the first arg: bare ident, or `arena.allocator()` chain.
        return self.argResolvesToArenaBound(args[0]);
    }

    /// `return switch (x) { ... }` — fork each arm's body off `cur`
    /// as its own basic block.  Diverging arms (those whose body
    /// `return` / `unreachable`) emit their own .ret with the right
    /// defer/errdefer flushes.  Non-diverging arms still produce a
    /// value that the outer .ret consumes; we don't try to thread
    /// that value back (the goal is bug detection, not type-check),
    /// so we just leak the forked block — it has no successor.
    ///
    /// No-op when `expr` isn't a switch.  Idempotent — called from
    /// lowerReturn after the try/catch/labeled-block dispatch.
    fn maybeLowerReturnSwitchArms(
        self: *Builder,
        expr: Ast.Node.Index,
        cur: *BlockId,
    ) (std.mem.Allocator.Error)!void {
        const tree = self.tree;
        switch (tree.nodeTag(expr)) {
            .@"switch", .switch_comma => {},
            else => return,
        }
        const sw = tree.fullSwitch(expr) orelse return;

        // Discriminant uses fire from the outer cur (before any arm).
        try self.emitUsesInExpr(sw.ast.condition, cur.*, null);

        for (sw.ast.cases) |case_node| {
            const case_full = tree.fullSwitchCase(case_node) orelse continue;
            const case_block = try self.newBlock();
            try self.addEdge(cur.*, case_block);
            if (case_full.payload_token) |pt| try self.registerCaptures(pt);
            var case_cur = case_block;
            // The arm body is the case's target_expr.  Block bodies
            // (`.err => { ... }`) lower naturally; naked expressions
            // (`.success => v`) end up as a lowering_gap, which is
            // harmless for state preservation.
            try self.lowerStmt(case_full.ast.target_expr, &case_cur);
            // Don't add an edge back to cur or anywhere — the arm is
            // a forked side-path used purely to surface bugs inside
            // diverging branches.  Adding an edge would propagate
            // arm-local state (free, deinit) back into the outer
            // return, causing spurious "use after free" downstream.
        }
    }

    /// True iff `expr` is syntactically a literal error return value
    /// (`error.X`).  Used by lowerReturn to decide whether to flush
    /// errdefers along with normal defers.  Conservative — only the
    /// directly-recognisable case; `return foo()` returning an error
    /// type stays as normal-only flush to avoid speculation.
    ///
    /// Also handles `try expr` wrapping a literal error (rare but
    /// possible: `return try error.X`).
    fn isLiteralErrorReturn(tree: *const Ast, expr: Ast.Node.Index) bool {
        switch (tree.nodeTag(expr)) {
            .error_value => return true,
            .@"try" => {
                const inner = tree.nodeData(expr).node;
                return isLiteralErrorReturn(tree, inner);
            },
            else => return false,
        }
    }

    fn isConstructorName(name: []const u8) bool {
        const list = [_][]const u8{
            "init", "create", "new", "open",
            "fromOwnedSlice", "fromSlice",
        };
        for (list) |n| if (std.mem.eql(u8, n, name)) return true;
        return false;
    }

    /// Infer the declared type of `var x = <init>` for the case where
    /// the var_decl has no explicit type annotation.  Lets call sites
    /// later resolve `x.method()` / `x.<borrowed_field>` via the type
    /// of the constructor's receiver, even when the user wrote no
    /// `: T` annotation.
    ///
    /// Recognises:
    ///   - `T.init(...)` / `T.create(...)` / `T.new(...)` / `T.open(...)`
    ///     and the other constructor-method names.
    ///   - `try <constructor-call>` — recurses past `try`.
    ///   - `T{ ... }` and `T.{ ... }` struct literals — but NOT
    ///     anonymous `.{ ... }`, which needs the surrounding context's
    ///     type that we don't have.
    /// Returns the LAST identifier in a dotted chain
    /// (`lib.Owner.init(...)` → "Owner"), matching extractTypeName's
    /// namespace-stripping rule.
    fn inferTypeNameFromInit(self: *Builder, init_node: Ast.Node.Index) ?[]const u8 {
        const tree = self.tree;
        var node = init_node;
        // Unwrap `try` and `<lhs> catch <fallback>` — both leave the
        // success-path value with the inner call's identity.
        while (true) {
            switch (tree.nodeTag(node)) {
                .@"try" => node = tree.nodeData(node).node,
                .@"catch" => node = tree.nodeData(node).node_and_node[0],
                else => break,
            }
        }
        switch (tree.nodeTag(node)) {
            .call, .call_one, .call_comma, .call_one_comma => {
                var buf: [1]Ast.Node.Index = undefined;
                const call = tree.fullCall(&buf, node) orelse return null;
                const callee = call.ast.fn_expr;
                if (tree.nodeTag(callee) != .field_access) return null;
                const fa = tree.nodeData(callee).node_and_token;
                const method_name = tree.tokenSlice(fa[1]);
                if (!isConstructorName(method_name)) return null;
                return self.lastIdentInDottedChain(fa[0]);
            },
            .struct_init,
            .struct_init_comma,
            .struct_init_one,
            .struct_init_one_comma,
            => {
                var buf: [2]Ast.Node.Index = undefined;
                const si = tree.fullStructInit(&buf, node) orelse return null;
                const type_expr = si.ast.type_expr.unwrap() orelse return null;
                return self.lastIdentInDottedChain(type_expr);
            },
            else => return null,
        }
    }

    /// Return the LAST identifier token slice in a dotted chain.
    /// `lib.Owner` → "Owner", `Owner` → "Owner", anything else → null.
    fn lastIdentInDottedChain(self: *Builder, node: Ast.Node.Index) ?[]const u8 {
        const tree = self.tree;
        switch (tree.nodeTag(node)) {
            .identifier => return tree.tokenSlice(tree.nodeMainToken(node)),
            .field_access => {
                const fa = tree.nodeData(node).node_and_token;
                return tree.tokenSlice(fa[1]);
            },
            else => return null,
        }
    }

    /// Resolve an expression node to an arena-bound LocalId if
    /// possible: bare identifier whose init_hint is arena_local /
    /// arena_allocator, OR a call `<arena_local>.allocator()`.
    fn argResolvesToArenaBound(self: *Builder, arg_node: Ast.Node.Index) ?LocalId {
        const tree = self.tree;
        switch (tree.nodeTag(arg_node)) {
            .identifier => {
                const name = tree.tokenSlice(tree.nodeMainToken(arg_node));
                const id = self.name_to_local.get(name) orelse return null;
                const hint = self.locals.items[@intFromEnum(id)].init_hint;
                if (hint == .arena_local or hint == .arena_allocator) return id;
                return null;
            },
            .call, .call_one, .call_comma, .call_one_comma => {
                return self.arenaLocalDotAllocatorReceiver(arg_node);
            },
            else => return null,
        }
    }

    /// Specifically detect `<arena_local>.allocator()` — receiver
    /// must be a bare identifier resolving to an arena_local.  Used
    /// to mint the .arena_allocator alias.
    fn arenaLocalDotAllocatorReceiver(self: *Builder, call_node: Ast.Node.Index) ?LocalId {
        const tree = self.tree;
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return null;
        const callee = call_full.ast.fn_expr;
        if (tree.nodeTag(callee) != .field_access) return null;
        const fa = tree.nodeData(callee).node_and_token;
        const method = tree.tokenSlice(fa[1]);
        if (!std.mem.eql(u8, method, "allocator")) return null;
        const recv = fa[0];
        if (tree.nodeTag(recv) != .identifier) return null;
        const name = tree.tokenSlice(tree.nodeMainToken(recv));
        const id = self.name_to_local.get(name) orelse return null;
        if (self.locals.items[@intFromEnum(id)].init_hint != .arena_local) return null;
        return id;
    }

    fn classifyCall(self: *Builder, call_node: Ast.Node.Index) ExprKind {
        const tree = self.tree;

        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, call_node) orelse return .unknown;
        const callee_node = call_full.ast.fn_expr;
        const args = call_full.ast.params;

        switch (tree.nodeTag(callee_node)) {
            .field_access => {
                const fa_data = tree.nodeData(callee_node);
                const recv_node = fa_data.node_and_token[0];
                const method_tok = fa_data.node_and_token[1];
                const method_name = tree.tokenSlice(method_tok);

                // Distinguish method-style (`obj.f(args)` where
                // `obj` is a local — receiver IS arg 0) from
                // same-file namespace-style (`Type.f(args)` where
                // `Type` is the containing struct's name —
                // receiver IS the namespace, not a logical arg).
                // Without this, an inferred
                // `@returns borrowed_from(0)` on `Type.init(slice)`
                // would resolve param 0 to `Type` itself, missing
                // the actual borrow source.
                const recv_is_local = blk: {
                    if (tree.nodeTag(recv_node) != .identifier) break :blk false;
                    const recv_name = tree.tokenSlice(tree.nodeMainToken(recv_node));
                    break :blk self.name_to_local.contains(recv_name);
                };

                // 1. Same-file DB hit on method name.
                if (self.db) |db| {
                    if (db.lookup(method_name)) |entry| {
                        if (entry.annotation) |a| {
                            return self.applyAnnotationToCall(a, recv_node, args, recv_is_local);
                        }
                    }
                }

                // 2. Cross-file: receiver is a bare identifier (the
                //    imported namespace), method lives in that file's DB.
                if (self.lookupRemoteMethod(recv_node, method_name)) |annotation| {
                    // For cross-file: there's no `recv` in the explicit
                    // args list (since the receiver IS the namespace),
                    // so treat as a non-method-style call.
                    return self.applyAnnotationToCall(annotation, callee_node, args, false);
                }
                return .unknown;
            },
            .identifier => {
                const raw_name = tree.tokenSlice(tree.nodeMainToken(callee_node));
                // Resolve function-pointer binding: if the callee
                // identifier names a local that's bound to a fn, use
                // the bound fn's name for the DB lookup.
                const fn_name = self.resolveBoundCallee(raw_name);
                if (self.db) |db| {
                    if (db.lookup(fn_name)) |entry| {
                        if (entry.annotation) |a| {
                            return self.applyAnnotationToCall(a, callee_node, args, false);
                        }
                    }
                }
                return .unknown;
            },
            else => return .unknown,
        }
    }

    /// Walk every token in `expr_node` and emit a `.use` stmt for each
    /// identifier that resolves to a known local.  Skips identifiers
    /// preceded by `.` (field/method names) or `&` (address-of doesn't
    /// read the value).  Optional `skip_local` is excluded — used by
    /// assign to avoid emitting a use for the LHS target.  Dedupes so
    /// repeated mentions of the same local only emit one `.use`.
    const FieldRef = struct { parent: LocalId, name: []const u8 };

    /// Return a `{ parent, name }` ref for a LHS expression
    /// anchored at a known local.  Walks through `field_access`
    /// AND `array_access` nodes to find the leftmost identifier;
    /// the `name` is the source-slice of everything to the right.
    ///
    /// Handles:
    ///   `obj.f`              → { obj, "f" }
    ///   `obj.f.g`            → { obj, "f.g" }
    ///   `arr[0].field`       → { arr, "[0].field" }
    ///   `arr[i].field`       → { arr, "[i].field" }
    ///   `obj.array[0].field` → { obj, "array[0].field" }
    ///
    /// Index expressions are kept as source-text (preserving
    /// literal indices like `[0]`, variable indices like `[i]`,
    /// even compound expressions like `[i+1]`).  This means
    /// reads/writes with IDENTICAL index source-text share a
    /// state-key — `arr[0].f` matches `arr[0].f` but NOT
    /// `arr[1].f`, and `arr[i].f` matches another `arr[i].f` only
    /// when both spell `i` the same way.  Conservative for
    /// precision, intentional miss for "same logical index via
    /// different expression" patterns.
    ///
    /// Returns null when the chain doesn't bottom out at a bare
    /// known-local ident (`Type.field` namespace, deref, etc.).
    ///
    /// Used by lowerAssign to dispatch field-target writes to
    /// .field_assign — symmetric with the field_use prefix
    /// emission on reads — so deep-path reassignments
    /// (`o.inner.handle = fresh()`) correctly RESET the freed
    /// state recorded by R10's N-level chain inference.
    fn fieldLhsFor(self: *Builder, lhs: Ast.Node.Index) ?FieldRef {
        const tree = self.tree;
        // Walk down field_access / array_access nodes to the root.
        // Array_access nodes are only accepted when the index is a
        // LITERAL CONSTANT (`arr[0]`, not `arr[i]`).  Variable
        // indices would mean the same source expression refers to
        // different elements on different evaluations — keying
        // state by literal source would FP across loop iterations.
        var cur = lhs;
        while (true) {
            switch (tree.nodeTag(cur)) {
                .field_access => {
                    cur = tree.nodeData(cur).node_and_token[0];
                },
                .array_access => {
                    const idx_node = tree.nodeData(cur).node_and_node[1];
                    if (tree.nodeTag(idx_node) != .number_literal) return null;
                    cur = tree.nodeData(cur).node_and_node[0];
                },
                .identifier => break,
                else => return null,
            }
        }
        // Must have actually descended from at least one
        // field_access / array_access — a bare identifier LHS
        // (`x = ...`) goes through a different path.
        if (cur == lhs) return null;
        const recv_name = tree.tokenSlice(tree.nodeMainToken(cur));
        const parent = self.name_to_local.get(recv_name) orelse return null;
        // Build the path: everything in source between the end of
        // the root ident and the end of the LHS.  If the next
        // char after the root is `.` (field access), skip it so
        // the path doesn't have a leading dot.  If it's `[`
        // (array access), include it — `[0].f` is the canonical
        // form.
        const root_tok = tree.nodeMainToken(cur);
        const root_start = tree.tokens.items(.start)[root_tok];
        const root_len = tree.tokenSlice(root_tok).len;
        var first_path_byte: usize = root_start + root_len;
        if (first_path_byte < tree.source.len and tree.source[first_path_byte] == '.') {
            first_path_byte += 1;
        }
        const last_tok = tree.lastToken(lhs);
        const last_start = tree.tokens.items(.start)[last_tok];
        const last_len = tree.tokenSlice(last_tok).len;
        const path = tree.source[first_path_byte..(last_start + last_len)];
        return .{ .parent = parent, .name = path };
    }

    /// True if `lhs_node` is `<local>.*` where `local` is pointer-
    /// typed.  Returns the local id when it matches.  Used to
    /// dispatch deref-writes to `out_param_write` for escape checks.
    fn derefOfPointerLocal(self: *Builder, lhs_node: Ast.Node.Index) ?LocalId {
        const tree = self.tree;
        if (tree.nodeTag(lhs_node) != .deref) return null;
        const inner = tree.nodeData(lhs_node).node;
        if (tree.nodeTag(inner) != .identifier) return null;
        const name = tree.tokenSlice(tree.nodeMainToken(inner));
        const id = self.name_to_local.get(name) orelse return null;
        if (!self.locals.items[@intFromEnum(id)].is_pointer) return null;
        return id;
    }

    /// `.field_name = <value>` field initializer in a struct literal:
    /// return the field name token's slice.  Recognises the canonical
    /// shape (a value preceded by `.name =`), returns null on
    /// positional inits (tuples) or shapes we don't expect.
    fn fieldInitName(self: *Builder, field_value: Ast.Node.Index) ?[]const u8 {
        const tree = self.tree;
        const first = tree.firstToken(field_value);
        if (first < 3) return null;
        const tags = tree.tokens.items(.tag);
        if (tags[first - 1] != .equal) return null;
        if (tags[first - 2] != .identifier) return null;
        if (tags[first - 3] != .period) return null;
        return tree.tokenSlice(first - 2);
    }

    /// Build a dotted path `prefix.leaf` and stash the allocated bytes
    /// in `owned_paths` so the resulting slice outlives the lowering
    /// pass.  If `prefix` is null, returns `leaf` unchanged (no
    /// allocation).
    fn allocDottedPath(self: *Builder, prefix: ?[]const u8, leaf: []const u8) ![]const u8 {
        const p = prefix orelse return leaf;
        const bytes = try std.fmt.allocPrint(self.gpa, "{s}.{s}", .{ p, leaf });
        errdefer self.gpa.free(bytes);
        try self.owned_paths.append(self.gpa, bytes);
        return bytes;
    }

    /// Unpack a struct-literal RHS into per-field `field_assign`
    /// statements so that aliases buried inside the literal are
    /// tracked by name.  Example: for `install.ca = .{ .str = buf }`
    /// (`parent = install`, `prefix = "ca"`), emit
    /// `field_assign(install, "ca.str", copy_of(buf))`.
    ///
    /// Recurses into nested struct literals so deeper aliases
    /// (`outer.inner = .{ .a = .{ .b = ptr } }`) are flattened too.
    /// This is purely additive — the existing `assign` /
    /// `field_assign` for the whole RHS is still emitted by the
    /// caller and remains the source of truth for the local /
    /// outermost field's own origin.
    fn unpackStructInitFields(
        self: *Builder,
        cur: BlockId,
        parent: LocalId,
        prefix: ?[]const u8,
        rhs_node: Ast.Node.Index,
        pos: SrcPos,
        end_pos: SrcPos,
    ) std.mem.Allocator.Error!void {
        const tree = self.tree;
        var buf: [2]Ast.Node.Index = undefined;
        const init = tree.fullStructInit(&buf, rhs_node) orelse return;
        for (init.ast.fields) |field_value| {
            const leaf = self.fieldInitName(field_value) orelse continue;
            const path = try self.allocDottedPath(prefix, leaf);
            try self.appendStmt(cur, .{
                .kind = .{ .field_assign = .{
                    .parent = parent,
                    .name = path,
                    .rhs_kind = self.classifyExpr(field_value),
                } },
                .pos = pos,
                .end_pos = end_pos,
            });
            try self.unpackStructInitFields(cur, parent, path, field_value, pos, end_pos);
        }
    }

    /// Walk LHS tokens of an assignment with a non-identifier target
    /// and emit one assign(id, .unknown) per distinct known-local
    /// mentioned.  Used to clear .undef on locals written through
    /// field access, indexing, or builtin pseudo-LHS like @field.
    fn emitWritesInLhs(
        self: *Builder,
        lhs_node: Ast.Node.Index,
        cur: BlockId,
    ) !void {
        const tree = self.tree;
        const first = tree.firstToken(lhs_node);
        const last = tree.lastToken(lhs_node);
        const tags = tree.tokens.items(.tag);
        const pos = self.posOf(lhs_node);
        const end_pos = self.endPosOf(lhs_node);

        var seen: std.AutoArrayHashMapUnmanaged(LocalId, void) = .empty;
        defer seen.deinit(self.gpa);

        var t: Ast.TokenIndex = first;
        while (t <= last) : (t += 1) {
            if (tags[t] != .identifier) continue;
            if (t > 0 and tags[t - 1] == .period) continue;
            const name = tree.tokenSlice(t);
            const id = self.name_to_local.get(name) orelse continue;
            const gop = try seen.getOrPut(self.gpa, id);
            if (gop.found_existing) continue;
            // `arena.* = X` / `obj.field = X` — writes THROUGH the
            // local, doesn't rebind it.  The local's resource
            // identity (.heap / .arena / .arena_borrow) is unchanged;
            // only an .undef may have been initialized.  Emit
            // assign-via-pointer-write that only clears .undef →
            // .plain in transferAssign, preserving resource origins.
            try self.appendStmt(cur, .{
                .kind = .{ .pointer_write = .{ .target = id } },
                .pos = pos,
                .end_pos = end_pos,
            });
        }
    }

    fn emitUsesInExpr(
        self: *Builder,
        expr_node: Ast.Node.Index,
        cur: BlockId,
        skip_local: ?LocalId,
    ) !void {
        const tree = self.tree;
        const first = tree.firstToken(expr_node);
        const last = tree.lastToken(expr_node);
        const tags = tree.tokens.items(.tag);

        // Use the whole-expression pos for every emitted stmt.  Per-
        // token positions (posOfToken) are O(byte_offset) — calling
        // that once per identifier turns analysis quadratic on large
        // files.  Coarser diagnostic, but cheap.
        const pos = self.posOf(expr_node);
        const end_pos = self.endPosOf(expr_node);

        var used: std.AutoArrayHashMapUnmanaged(LocalId, void) = .empty;
        defer used.deinit(self.gpa);
        var aw: std.AutoArrayHashMapUnmanaged(LocalId, void) = .empty;
        defer aw.deinit(self.gpa);

        // Comptime-only builtin parens: `@TypeOf(local)`, `@sizeOf`,
        // `@alignOf`, `@typeInfo`, etc. don't EVALUATE their argument
        // at runtime — they query the type.  Idents inside such a
        // paren range must NOT be treated as runtime reads, or
        // `var x: T = undefined; @sizeOf(@TypeOf(x))` trips use_undefined.
        var paren_depth: u32 = 0;
        var comptime_skip_active: bool = false;
        var comptime_skip_until: u32 = 0;

        var t: Ast.TokenIndex = first;
        while (t <= last) : (t += 1) {
            const tag = tags[t];
            if (tag == .l_paren) {
                paren_depth += 1;
                if (!comptime_skip_active and t > 0 and tags[t - 1] == .builtin and
                    isComptimeOnlyBuiltin(tree.tokenSlice(t - 1)))
                {
                    comptime_skip_active = true;
                    comptime_skip_until = paren_depth - 1;
                }
                continue;
            }
            if (tag == .r_paren) {
                if (paren_depth > 0) paren_depth -= 1;
                if (comptime_skip_active and paren_depth == comptime_skip_until) {
                    comptime_skip_active = false;
                }
                continue;
            }
            if (comptime_skip_active) continue;
            if (tag != .identifier) continue;
            // LHS of a plain `=` assignment inside a sub-expression
            // (e.g. a switch arm body or labeled block being used as
            // the init of an outer var_decl).  Those inner assignments
            // are NOT lowered as their own .assign statements (the
            // whole containing expression is one node from the
            // var_decl lowerer's perspective), so without recording
            // the write here a later read of the same local inside
            // the same expression spuriously sees .undef.  Emit
            // .assign(.unknown) — rhs origin is opaque from a token
            // walk, but clearing undef is what matters.
            if (t + 1 <= last and tags[t + 1] == .equal) {
                const lhs_name = tree.tokenSlice(t);
                if (self.name_to_local.get(lhs_name)) |lid| {
                    if (skip_local == null or skip_local.? != lid) {
                        const gop_w = try aw.getOrPut(self.gpa, lid);
                        if (!gop_w.found_existing) {
                            try self.appendStmt(cur, .{
                                .kind = .{ .assign = .{ .target = lid, .rhs_kind = .unknown } },
                                .pos = pos,
                                .end_pos = end_pos,
                            });
                        }
                    }
                }
                continue;
            }
            // Address-of: `&id` is conservatively treated as a possible
            // write (out-param pattern).  Emit an .assign with .unknown
            // rhs so the local's origin collapses to .plain — clears
            // .undef and avoids spurious use-of-undefined findings on
            // common idioms like `var x = undefined; fillOut(&x);`.
            //
            // EXCEPTION: arena/heap-bearing locals.  Their resource
            // identity is stable across `&x` (the address-of doesn't
            // re-bind the underlying allocator), so clearing would
            // mask real escape findings — e.g. `return wrap(&arena)`
            // depends on arena's .arena origin surviving to the .ret.
            if (t > 0 and tags[t - 1] == .ampersand) {
                const name = tree.tokenSlice(t);
                const id = self.name_to_local.get(name) orelse continue;
                if (skip_local) |s| if (id == s) continue;
                const hint = self.locals.items[@intFromEnum(id)].init_hint;
                if (hint != .other) continue;
                const gop = try aw.getOrPut(self.gpa, id);
                if (gop.found_existing) continue;
                try self.appendStmt(cur, .{
                    .kind = .{ .assign = .{ .target = id, .rhs_kind = .unknown } },
                    .pos = pos,
                    .end_pos = end_pos,
                });
                continue;
            }
            // Field/method access: `.method` — skip; it's not a local.
            if (t > 0 and tags[t - 1] == .period) continue;
            // Structural / comptime access on the next token that
            // doesn't actually read the local's contents:
            //   `id[..]` `id[i]`  — slice / index (creates pointer)
            //   `id.len`          — comptime length on an array
            //   `id.ptr`          — pointer-of on a slice/array
            //   `id: T`           — struct-field declaration shape;
            //                       `id` is a NAME, not a value read.
            //                       (Same for loop / block labels.)
            // Treating these as value reads produces noisy false
            // positives on stack buffers declared `= undefined` and
            // on identifiers that shadow an outer local inside an
            // anonymous struct type.
            var ident_in_method_recv_pos = false;
            if (t + 1 <= last) {
                const next = tags[t + 1];
                if (next == .l_bracket) {
                    // `id[…].<field>` — subscript followed by field
                    // access.  Emit a field_use with the subscript-
                    // prefixed path so the read matches what
                    // `fieldLhsFor` records on writes / frees.
                    // Scan past the matched `]` and require a `.<ident>`
                    // immediately after.
                    if (self.subscriptFieldPath(t, last)) |info| {
                        const name = tree.tokenSlice(t);
                        if (self.name_to_local.get(name)) |id| {
                            try self.appendStmt(cur, .{
                                .kind = .{ .field_use = .{ .parent = id, .name = info.path } },
                                .pos = pos,
                                .end_pos = end_pos,
                            });
                        }
                    }
                    continue;
                }
                if (next == .colon) continue;
                if (next == .period and t + 2 <= last and tags[t + 2] == .identifier) {
                    const field = tree.tokenSlice(t + 2);
                    if (std.mem.eql(u8, field, "len") or std.mem.eql(u8, field, "ptr")) continue;
                    // Distinguish field access (`x.f`), accessor
                    // method (`x.f()` reads x), and mutator method
                    // (`x.init(...)` writes x — common pattern is
                    // `var s: T = undefined; s.init(...);`).
                    const is_method_call = t + 3 <= last and tags[t + 3] == .l_paren;
                    ident_in_method_recv_pos = is_method_call;
                    const name = tree.tokenSlice(t);
                    if (self.name_to_local.get(name)) |id| {
                        if (is_method_call) {
                            if (isMutatorMethodName(field)) {
                                // Treat as write: clear undef.  Same
                                // shape as &<local> address-of write.
                                if (skip_local == null or skip_local.? != id) {
                                    const hint = self.locals.items[@intFromEnum(id)].init_hint;
                                    if (hint == .other) {
                                        const gop = try aw.getOrPut(self.gpa, id);
                                        if (!gop.found_existing) {
                                            try self.appendStmt(cur, .{
                                                .kind = .{ .assign = .{ .target = id, .rhs_kind = .unknown } },
                                                .pos = pos,
                                                .end_pos = end_pos,
                                            });
                                        }
                                    }
                                }
                                continue;
                            }
                            // Accessor: fall through to .use emission.
                        } else {
                            // Field-access read.  Emit a field_use
                            // for EVERY prefix of the dotted-chain
                            // path so:
                            //   - If `obj.f1` is freed, reading
                            //     `obj.f1.f2.f3` still fires UAF
                            //     (the "f1" prefix matches).
                            //   - If `obj.f1.f2` is freed (via R10
                            //     chain inference), reading
                            //     `obj.f1.f2.f3` ALSO fires (the
                            //     "f1.f2" prefix matches).
                            // Trailing-method idents (`obj.f1.f2.m(`)
                            // are excluded from the path by
                            // `fieldChainPath`.
                            try self.emitFieldUsePrefixes(cur, id, t, last, pos, end_pos);
                            continue;
                        }
                    } else if (!is_method_call) {
                        continue;
                    }
                }
            }
            const name = tree.tokenSlice(t);
            const id = self.name_to_local.get(name) orelse continue;
            if (skip_local) |s| if (id == s) continue;
            const gop = try used.getOrPut(self.gpa, id);
            if (gop.found_existing) continue;
            try self.appendStmt(cur, .{
                .kind = .{ .use = .{ .local = id, .from_method_call = ident_in_method_recv_pos } },
                .pos = pos,
                .end_pos = end_pos,
            });
        }
    }

    /// Cross-file annotation lookup.  When the call shape is
    /// `<imported>.<method>(...)`, resolve `imported` through the
    /// local imap to a path, load that file's annotation DB through
    /// the sweep-wide remote cache, and return `method`'s annotation
    /// (if any).  Returns null on any miss — never errors; callers
    /// must treat missing remote info as "no annotation."
    fn lookupRemoteMethod(
        self: *Builder,
        recv_node: Ast.Node.Index,
        method_name: []const u8,
    ) ?annotations.ReturnsAnnotation {
        const remote = self.remote orelse return null;
        const tree = self.tree;
        if (tree.nodeTag(recv_node) != .identifier) return null;
        const recv_name = tree.tokenSlice(tree.nodeMainToken(recv_node));
        const imap_entry = remote.imap.lookup(recv_name) orelse return null;
        const remote_file = (remote.cache.loadOrLookup(remote.base_dir, imap_entry.path) catch return null) orelse return null;
        const entry = remote_file.db.lookup(method_name) orelse return null;
        return entry.annotation;
    }

    fn applyAnnotationToCall(
        self: *Builder,
        anno: annotations.ReturnsAnnotation,
        receiver_or_callee: Ast.Node.Index,
        args: []const Ast.Node.Index,
        receiver_is_arg0: bool,
    ) ExprKind {
        switch (anno) {
            .owned => return .owned,
            .borrowed_from => |target_idx| {
                if (receiver_is_arg0 and target_idx == 0) {
                    return self.identifierToCopyOrUnknown(receiver_or_callee);
                }
                const explicit_idx = if (receiver_is_arg0) target_idx - 1 else target_idx;
                if (explicit_idx >= args.len) return .unknown;
                return self.identifierToCopyOrUnknown(args[explicit_idx]);
            },
            // owns_locals only affects the CALLEE's own analysis (it
            // suppresses composite-borrow detection inside that fn's
            // body).  At call sites it tells us nothing about the
            // returned value's lifetime beyond "the callee took
            // responsibility for whatever it embedded."  Treat as
            // .owned — caller has no remaining liability.
            .owns_locals => return .owned,
            // `@returns heap` — mint a HeapId at THIS call site so
            // downstream free/use tracking fires.  Same shape as a
            // direct `.heap_alloc` from the heap_alloc_patterns text
            // match.
            .heap => {
                const hid: abstract_state.HeapId = @enumFromInt(self.next_heap);
                self.next_heap += 1;
                return .{ .heap_alloc = hid };
            },
        }
    }

    /// If `node` resolves to a known local, return .copy_of(that
    /// local).  Looks through `&id` (address-of) so call args like
    /// `wrap(&local)` propagate the local's origin to the wrapper's
    /// inferred `borrowed_from`.
    fn identifierToCopyOrUnknown(self: *Builder, node: Ast.Node.Index) ExprKind {
        const tree = self.tree;
        const target = switch (tree.nodeTag(node)) {
            .identifier => node,
            .address_of => blk: {
                const inner = tree.nodeData(node).node;
                if (tree.nodeTag(inner) != .identifier) return .unknown;
                break :blk inner;
            },
            else => return .unknown,
        };
        const name = tree.tokenSlice(tree.nodeMainToken(target));
        if (self.name_to_local.get(name)) |id| return .{ .copy_of = id };
        return .unknown;
    }

    fn firstIdentifierLocal(self: *Builder, text: []const u8) ?LocalId {
        var i: usize = 0;
        // Skip leading whitespace
        while (i < text.len and (text[i] == ' ' or text[i] == '\t')) i += 1;
        const start = i;
        while (i < text.len) : (i += 1) {
            const c = text[i];
            if (!isIdentChar(c)) break;
        }
        if (i == start) return null;
        const name = text[start..i];
        return self.name_to_local.get(name);
    }

    /// Method names that conventionally MUTATE the receiver via
    /// `&self` pointer — `init`/`reset` initialize, `deinit`/`destroy`
    /// invalidate, etc.  These don't READ the receiver's current
    /// contents (init explicitly overwrites garbage), so emitting
    /// .use on them would spuriously fire `use of x while still
    /// undefined` for the canonical pattern:
    ///   var s: T = undefined;
    ///   s.init(...);
    fn isMutatorMethodName(name: []const u8) bool {
        // Prefix conventions: `init*` initializes, `set*` writes,
        // `reset*` reinitializes.  Covers `initEmpty`, `initBuffer`,
        // `initCapacity`, `setValue`, `resetState`, etc.
        if (std.mem.startsWith(u8, name, "init")) return true;
        if (std.mem.startsWith(u8, name, "set")) return true;
        if (std.mem.startsWith(u8, name, "reset")) return true;
        const list = [_][]const u8{
            "clear", "clearRetainingCapacity", "clearAndFree",
            "deinit", "destroy", "close",
            "open", "load", "loadFromDisk", "loadFromBytes",
            "fillFromPackageJSON",
        };
        for (list) |n| if (std.mem.eql(u8, n, name)) return true;
        return false;
    }

    /// Type-introspection / size-query builtins whose argument is
    /// evaluated at comptime and never read at runtime.  Idents inside
    /// these builtin parens must not count as runtime uses.
    fn isComptimeOnlyBuiltin(name: []const u8) bool {
        // `name` includes the leading `@`.
        const candidates = [_][]const u8{
            "@TypeOf", "@sizeOf", "@alignOf", "@bitSizeOf",
            "@typeInfo", "@typeName", "@hasField", "@hasDecl",
            "@offsetOf", "@bitOffsetOf", "@fieldParentPtr",
        };
        for (candidates) |c| if (std.mem.eql(u8, name, c)) return true;
        return false;
    }

    /// Emit a `.field_use` for every PREFIX of the dotted chain
    /// starting at `obj` (token `t`): "f1", "f1.f2", "f1.f2.f3",
    /// etc.  This way a free recorded at any depth (e.g.
    /// `field_heap_free(obj, "f1")` from a shallow R8b match) and
    /// a free at the deepest path (from R10's N-level inference)
    /// both fire when the caller reads the deep access.
    fn emitFieldUsePrefixes(
        self: *Builder,
        cur: BlockId,
        parent: LocalId,
        t: Ast.TokenIndex,
        last: Ast.TokenIndex,
        pos: SrcPos,
        end_pos: SrcPos,
    ) (std.mem.Allocator.Error)!void {
        const tree = self.tree;
        const tags = tree.tokens.items(.tag);
        // Caller verified tags[t+1] == `.`, tags[t+2] = ident.
        const first_field: Ast.TokenIndex = t + 2;
        var chain_end: Ast.TokenIndex = first_field;
        while (chain_end + 2 <= last and tags[chain_end + 1] == .period and tags[chain_end + 2] == .identifier) {
            chain_end += 2;
        }
        const ends_in_call = chain_end + 1 <= last and tags[chain_end + 1] == .l_paren;
        // Last ident to INCLUDE in the field portion.  If the chain
        // ends with `(`, the final ident is a method name — skip it.
        const last_field: ?Ast.TokenIndex = if (ends_in_call)
            (if (chain_end > first_field) chain_end - 2 else null)
        else
            chain_end;
        if (last_field == null) return;
        // Emit one prefix per inclusive field ident.
        const start_byte = tree.tokens.items(.start)[first_field];
        var f: Ast.TokenIndex = first_field;
        while (f <= last_field.?) : (f += 2) {
            const f_start = tree.tokens.items(.start)[f];
            const f_len = tree.tokenSlice(f).len;
            const path = tree.source[start_byte..(f_start + f_len)];
            try self.appendStmt(cur, .{
                .kind = .{ .field_use = .{ .parent = parent, .name = path } },
                .pos = pos,
                .end_pos = end_pos,
            });
        }
    }

    /// `<id>[<literal>].<f>(.<g>)*` — return the path slice
    /// starting at `[` and extending through the final field
    /// ident.  Only LITERAL-CONSTANT subscripts are recognised
    /// (`arr[0]`, `arr[1]`) — variable indices (`arr[i]`, `arr[i+1]`)
    /// are skipped to avoid loop-iteration FPs where the same
    /// source expression refers to different elements on each
    /// iteration (most painful symptom: a loop that frees
    /// `arr[j].x` then increments `j` looks like a double-free
    /// to zbc).
    fn subscriptFieldPath(
        self: *Builder,
        t: Ast.TokenIndex,
        last: Ast.TokenIndex,
    ) ?struct { path: []const u8 } {
        const tree = self.tree;
        const tags = tree.tokens.items(.tag);
        if (t + 3 > last) return null;
        if (tags[t + 1] != .l_bracket) return null;
        if (tags[t + 2] != .number_literal) return null;
        if (tags[t + 3] != .r_bracket) return null;
        const pos: Ast.TokenIndex = t + 3; // `]`
        // pos now indexes the matching `]`.
        // Require `.<ident>` immediately after.
        if (pos + 2 > last) return null;
        if (tags[pos + 1] != .period) return null;
        if (tags[pos + 2] != .identifier) return null;
        // Extend the chain through further `.<ident>` segments.
        var chain_end: Ast.TokenIndex = pos + 2;
        while (chain_end + 2 <= last and tags[chain_end + 1] == .period and tags[chain_end + 2] == .identifier) {
            chain_end += 2;
        }
        // If chain ends with `(`, the last ident is a method.
        const ends_in_call = chain_end + 1 <= last and tags[chain_end + 1] == .l_paren;
        const last_field: ?Ast.TokenIndex = if (ends_in_call)
            (if (chain_end > pos + 2) chain_end - 2 else null)
        else
            chain_end;
        if (last_field == null) return null;
        // Path starts at the `[` token, ends at the last_field's end.
        const first_byte = tree.tokens.items(.start)[t + 1];
        const last_start = tree.tokens.items(.start)[last_field.?];
        const last_len = tree.tokenSlice(last_field.?).len;
        return .{ .path = tree.source[first_byte..(last_start + last_len)] };
    }

    /// Build the field-path source slice for a chain starting at
    /// `obj` (token `t`).  Token sequence: `<obj>` `.` `<f1>` (`.`
    /// `<f2>`)* [`(` …].  Returns the dotted source slice of the
    /// field segment (e.g. "f1.f2") — a single field for 1-deep,
    /// multi-segment for deeper.  When the trailing token after the
    /// final ident is `(`, that final ident is the method name and
    /// is excluded from the path.  Falls back to the immediate
    /// field name for any unexpected shape.
    fn fieldChainPath(tree: *const Ast, t: Ast.TokenIndex, last: Ast.TokenIndex) []const u8 {
        const tags = tree.tokens.items(.tag);
        // Caller has already verified tags[t+1] == `.`, tags[t+2] = ident.
        const first_field: Ast.TokenIndex = t + 2;
        var chain_end: Ast.TokenIndex = first_field;
        while (chain_end + 2 <= last and tags[chain_end + 1] == .period and tags[chain_end + 2] == .identifier) {
            chain_end += 2;
        }
        // If the chain ends with `<ident>(`, exclude that ident
        // (it's the method).
        const ends_in_call = chain_end + 1 <= last and tags[chain_end + 1] == .l_paren;
        const last_field: Ast.TokenIndex = if (ends_in_call) blk: {
            // The chain has at least 2 idents (the param's first
            // field + the method) only if chain_end > first_field.
            // If they're equal, there are NO field idents — just a
            // method call directly on the param.  Fall back to the
            // immediate ident (still emits the single field; though
            // realistically the caller's `is_method_call` branch
            // handles this path).
            if (chain_end <= first_field) break :blk first_field;
            break :blk chain_end - 2;
        } else chain_end;
        const start_byte = tree.tokens.items(.start)[first_field];
        const last_start = tree.tokens.items(.start)[last_field];
        const last_len = tree.tokenSlice(last_field).len;
        return tree.source[start_byte..(last_start + last_len)];
    }

    fn isIdentChar(c: u8) bool {
        return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '_';
    }

    /// For a call-like node, return the source-text slice covering
    /// just the callee expression (the `f` in `f(...)`).  Lets pattern
    /// matches that should target the function being called avoid
    /// accidentally matching identifiers buried in the args.  Returns
    /// null when `expr_node` is not a call shape.
    fn calleeText(self: *Builder, expr_node: Ast.Node.Index) ?[]const u8 {
        const tree = self.tree;
        switch (tree.nodeTag(expr_node)) {
            .call, .call_one, .call_comma, .call_one_comma => {},
            else => return null,
        }
        var buf: [1]Ast.Node.Index = undefined;
        const call_full = tree.fullCall(&buf, expr_node) orelse return null;
        const callee = call_full.ast.fn_expr;
        const first = tree.firstToken(callee);
        const last = tree.lastToken(callee);
        const start = tree.tokens.items(.start)[first];
        const last_start = tree.tokens.items(.start)[last];
        const last_len = tree.tokenSlice(last).len;
        return tree.source[start..(last_start + last_len)];
    }

    fn posOf(self: *Builder, node: Ast.Node.Index) SrcPos {
        return self.posOfToken(self.tree.firstToken(node));
    }

    /// End position (exclusive) — one past the last token of `node`.
    /// Walks lastToken's start + slice length.  Used together with
    /// posOf to give diagnostics a real span the editor can highlight.
    fn endPosOf(self: *Builder, node: Ast.Node.Index) SrcPos {
        const tree = self.tree;
        const last = tree.lastToken(node);
        const start = tree.tokens.items(.start)[last];
        const slice = tree.tokenSlice(last);
        const end_byte: u32 = @intCast(start + slice.len);
        const loc = tree.tokenLocation(0, last);
        return .{
            .byte = end_byte,
            .line = @intCast(loc.line + 1),
            .column = @intCast(loc.column + 1 + slice.len),
        };
    }

    fn posOfToken(self: *Builder, tok: Ast.TokenIndex) SrcPos {
        const tree = self.tree;
        const start = tree.tokens.items(.start)[tok];
        const loc = tree.tokenLocation(0, tok);
        return .{
            .byte = start,
            .line = @intCast(loc.line + 1),
            .column = @intCast(loc.column + 1),
        };
    }

    /// End-of-token (exclusive) position.  Single-token analog of
    /// endPosOf.
    fn posOfTokenEnd(self: *Builder, tok: Ast.TokenIndex) SrcPos {
        const tree = self.tree;
        const start = tree.tokens.items(.start)[tok];
        const slice = tree.tokenSlice(tok);
        const end_byte: u32 = @intCast(start + slice.len);
        const loc = tree.tokenLocation(0, tok);
        return .{
            .byte = end_byte,
            .line = @intCast(loc.line + 1),
            .column = @intCast(loc.column + 1 + slice.len),
        };
    }

    fn finalize(
        self: *Builder,
        tree: *const Ast,
        fn_decl: Ast.Node.Index,
        entry: BlockId,
    ) !Cfg {
        const blocks = try self.gpa.alloc(BasicBlock, self.blocks.items.len);
        for (self.blocks.items, 0..) |bb, i| {
            blocks[i] = .{
                .id = bb.id,
                .stmts = try self.block_stmts.items[i].toOwnedSlice(self.gpa),
                .successors = try self.block_successors.items[i].toOwnedSlice(self.gpa),
            };
        }
        const locals = try self.locals.toOwnedSlice(self.gpa);
        const owned_paths = try self.owned_paths.toOwnedSlice(self.gpa);
        const start = tree.tokens.items(.start)[tree.firstToken(fn_decl)];
        const end_tok = tree.lastToken(fn_decl);
        const end = tree.tokens.items(.start)[end_tok] + tree.tokenSlice(end_tok).len;
        return .{
            .blocks = blocks,
            .entry = entry,
            .fn_span = .{ .start = start, .end = @intCast(end) },
            .locals = locals,
            .owned_paths = owned_paths,
        };
    }
};

/// True iff the return-type node text starts with `*` or `[` after
/// stripping leading `?` / `E!`.  Same heuristic the Layer-1 rule uses
/// (require_borrowed_from.zig) — Node.Data variant churn between Zig
/// versions makes source-text inspection more robust than the typed
/// API.
fn returnTypeIsBorrowed(tree: *const Ast, node: Ast.Node.Index) bool {
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    const start = tree.tokens.items(.start)[first];
    const last_start = tree.tokens.items(.start)[last];
    const last_len = tree.tokenSlice(last).len;
    const end: usize = last_start + last_len;
    var text = tree.source[start..end];
    while (text.len > 0) {
        switch (text[0]) {
            '?', '!', ' ', '\t' => text = text[1..],
            else => break,
        }
    }
    if (std.mem.indexOfScalar(u8, text, '!')) |bang| {
        text = std.mem.trimStart(u8, text[bang + 1 ..], " \t");
    }
    return text.len > 0 and (text[0] == '*' or text[0] == '[');
}

/// Returns the statements of a block node.  Zig's AST has 4 block variants
/// depending on statement count + trailing semicolon.
fn blockStmts(
    tree: *const Ast,
    block_node: Ast.Node.Index,
    buf: *[2]Ast.Node.Index,
) []const Ast.Node.Index {
    return switch (tree.nodeTag(block_node)) {
        .block, .block_semicolon => tree.extraDataSlice(tree.nodeData(block_node).extra_range, Ast.Node.Index),
        .block_two, .block_two_semicolon => blk: {
            const data = tree.nodeData(block_node);
            buf[0] = data.opt_node_and_opt_node[0].unwrap() orelse break :blk &.{};
            if (data.opt_node_and_opt_node[1].unwrap()) |second| {
                buf[1] = second;
                break :blk buf[0..2];
            }
            break :blk buf[0..1];
        },
        else => &.{},
    };
}

// ── Tests ──────────────────────────────────────────────────

/// Test bundle returned by `parseAndLower`.  Owns src_z so name
/// slices in cfg.locals (which point into tree.source = src_z) stay
/// valid for the bundle's lifetime.  Pre-phase-20 src_z was freed
/// on parseAndLower's return, which dangled the names — tests that
/// inspected names saw garbage.
const TestBundle = struct {
    src_z: [:0]u8,
    tree: Ast,
    cfg: ?Cfg,

    fn deinit(self: *TestBundle, gpa: std.mem.Allocator) void {
        if (self.cfg) |*c| c.deinit(gpa);
        self.tree.deinit(gpa);
        gpa.free(self.src_z);
    }
};

fn parseAndLower(gpa: std.mem.Allocator, src: []const u8) !TestBundle {
    return parseAndLowerCommon(gpa, src, false);
}

/// Same as parseAndLower but builds the same-file annotation DB and
/// threads it through lowerFunction.  Use when tests exercise the
/// annotated-call classification paths.  Db is intentionally leaked
/// — its keys/values point into tree.source which the bundle owns.
fn parseAndLowerWithDb(gpa: std.mem.Allocator, src: []const u8) !TestBundle {
    return parseAndLowerCommon(gpa, src, true);
}

fn parseAndLowerCommon(gpa: std.mem.Allocator, src: []const u8, build_db: bool) !TestBundle {
    const src_z = try gpa.dupeSentinel(u8, src, 0);
    errdefer gpa.free(src_z);
    var tree = try Ast.parse(gpa, src_z, .zig);
    errdefer tree.deinit(gpa);

    var db_storage: ?annotations.Db = if (build_db) try annotations.build(gpa, &tree) else null;
    // Db owns only its map; deinit'd at bundle.deinit via leak-into-cfg
    // pattern is wrong — we need to deinit it manually.  Easiest: free
    // here on the success path too, since cfg only borrows annotation
    // VALUES (which are small union types), not slice keys.  Wait — db
    // is consulted DURING lowerFunction, then no longer needed once
    // CFG emit completes.  Free immediately after lowerFunction returns.
    defer if (db_storage) |*d| d.deinit(gpa);

    var node_idx: u32 = 1;
    while (node_idx < tree.nodes.len) : (node_idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(node_idx);
        if (tree.nodeTag(node) == .fn_decl) {
            const db_ptr: ?*const annotations.Db = if (db_storage) |*d| d else null;
            const cfg = try lowerFunction(gpa, &tree, node, db_ptr);
            return .{ .src_z = src_z, .tree = tree, .cfg = cfg };
        }
    }
    return .{ .src_z = src_z, .tree = tree, .cfg = null };
}

test "lower trivial fn — entry block + return" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // 2 blocks: entry (with ret) and the dead post-return block.
    try std.testing.expectEqual(@as(usize, 2), cfg.blocks.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.blocks[0].stmts.len);
    try std.testing.expect(cfg.blocks[0].stmts[0].kind == .ret);
}

test "lower fn with var decl + arena init + deinit" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\const std = @import("std");
        \\pub fn foo() void {
        \\    var arena = std.heap.ArenaAllocator.init(undefined);
        \\    arena.deinit();
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // 2 blocks (entry + dead post-return); entry has 3 stmts: decl,
    // arena_kill, ret.
    try std.testing.expectEqual(@as(usize, 2), cfg.blocks.len);
    const stmts = cfg.blocks[0].stmts;
    try std.testing.expectEqual(@as(usize, 3), stmts.len);

    try std.testing.expect(stmts[0].kind == .decl);
    try std.testing.expect(stmts[0].kind.decl.init_kind == .arena_init);

    try std.testing.expect(stmts[1].kind == .arena_kill);
    // Receiver local should be the same as the declared local.
    try std.testing.expectEqual(stmts[0].kind.decl.local, stmts[1].kind.arena_kill.arena_local);

    try std.testing.expect(stmts[2].kind == .ret);
}

test "lower fn with return of borrowed identifier" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() u32 {
        \\    var x = bar();
        \\    return x;
        \\}
        \\fn bar() u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    const stmts = cfg.blocks[0].stmts;
    // decl x, use x (emitted before the ret), ret x.
    try std.testing.expectEqual(@as(usize, 3), stmts.len);
    try std.testing.expect(stmts[0].kind == .decl);
    try std.testing.expect(stmts[1].kind == .use);
    try std.testing.expect(stmts[2].kind == .ret);
    try std.testing.expect(stmts[2].kind.ret.value_kind == .copy_of);
    try std.testing.expectEqual(stmts[0].kind.decl.local, stmts[2].kind.ret.value_kind.copy_of);
    try std.testing.expectEqual(stmts[0].kind.decl.local, stmts[1].kind.use.local);
}

test "if-statement creates fork: 3 blocks (entry, then, merge)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    if (x) return;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Entry, then-branch, merge.  No else (single-armed if).
    try std.testing.expect(cfg.blocks.len >= 3);
    // Entry block has 2 successors (then + merge).
    try std.testing.expectEqual(@as(usize, 2), cfg.blocks[0].successors.len);
}

test "if-else creates fork: 4 blocks (entry, then, else, merge)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    if (x) return else return;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    try std.testing.expect(cfg.blocks.len >= 4);
    try std.testing.expectEqual(@as(usize, 2), cfg.blocks[0].successors.len);
}

test "for loop creates back-edge: body → header" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(items: []const u32) void {
        \\    for (items) |x| { _ = x; }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;
    // entry, header, body, merge (minimum 4 blocks).
    try std.testing.expect(cfg.blocks.len >= 4);
}

test "switch creates N-way fork (3 cases → 4+ blocks)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: u32) void {
        \\    switch (x) {
        \\        0 => return,
        \\        1 => return,
        \\        else => return,
        \\    }
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;
    // entry + 3 case-blocks + merge = 5 blocks min.
    try std.testing.expect(cfg.blocks.len >= 5);
    // entry has 3 successors (one per case).
    try std.testing.expectEqual(@as(usize, 3), cfg.blocks[0].successors.len);
}

test "while loop creates back-edge: body → header" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    while (x) {}
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // header block has 2 successors (body, merge); body block has 1
    // successor (back to header).  At minimum we expect 4 blocks:
    // entry, header, body, merge.
    try std.testing.expect(cfg.blocks.len >= 4);
}

test "errdefer kill doesn't pollute success-return defer flush" {
    // errdefer arena.deinit() must NOT fire on a plain `return` —
    // otherwise the (returned-value) origin check would see arena
    // already-killed and wrongly flag the return.
    //
    // NOTE: parseAndLower picks the FIRST fn_decl, so `foo` must lead.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    errdefer arena.deinit();
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Scan every block's stmts: no `.arena_kill` should appear before
    // the `.ret`.  (Without the defer/errdefer split, errdefer's kill
    // would have been replayed at the return site.)
    var saw_kill_before_ret = false;
    var saw_ret = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            switch (s.kind) {
                .arena_kill => if (!saw_ret) {
                    saw_kill_before_ret = true;
                },
                .ret => saw_ret = true,
                else => {},
            }
        }
    }
    try std.testing.expect(!saw_kill_before_ret);
}

test "plain defer DOES fire on return — kill visible before ret stmt" {
    // Symmetric to the errdefer test: a normal `defer` must still
    // replay at every return so the analyzer sees its side effects.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_kill = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) saw_kill = true;
        }
    }
    try std.testing.expect(saw_kill);
}

test "try at statement position creates error-exit sink with defers replayed" {
    // `try call();` — adds an error-exit block reachable from cur.
    // The sink should contain whatever defers were active (here:
    // arena.deinit() from `defer`) and a terminating ret.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !void {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    try sideEffect();
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !void {}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // After `try`, at least one block must have BOTH an arena_kill
    // (the defer'd deinit) AND a ret — that's the err_exit sink.
    var found_err_sink = false;
    for (cfg.blocks) |b| {
        var has_kill = false;
        var has_ret = false;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) has_kill = true;
            if (s.kind == .ret) has_ret = true;
        }
        if (has_kill and has_ret) found_err_sink = true;
    }
    try std.testing.expect(found_err_sink);
}

test "catch at statement position forks: success + catch body merge" {
    // `expr catch BODY;` — two paths join at a merge block.  Minimum
    // block count: entry + catch + merge = 3.  (entry also acts as
    // the success-edge source via direct edge to merge.)
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    sideEffect() catch {};
        \\    return;
        \\}
        \\pub fn sideEffect() !void {}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    try std.testing.expect(cfg.blocks.len >= 3);

    // The entry block must have ≥2 successors after catch lowering
    // (one to catch_block, one to merge).
    var multi_succ = false;
    for (cfg.blocks) |b| {
        if (b.successors.len >= 2) multi_succ = true;
    }
    try std.testing.expect(multi_succ);
}

test "catch body side effects visible at merge (kill in catch reaches downstream)" {
    // Arena killed only inside the catch body — at the merge point
    // it should be in the "either-killed-or-alive" state.  The
    // analyzer's join semantics (dead-on-either-side wins) means
    // downstream uses would be flagged.  Here we just verify the
    // arena_kill ends up in some non-entry block.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    sideEffect() catch { arena.deinit(); };
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !void {}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Find an arena_kill — should appear in a non-entry block (the
    // catch_block specifically, but we don't care which).
    var kill_in_non_entry = false;
    for (cfg.blocks, 0..) |b, i| {
        if (i == 0) continue;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) kill_in_non_entry = true;
        }
    }
    try std.testing.expect(kill_in_non_entry);
}

test "var-decl init `try foo()` adds error-exit sink with defer replayed" {
    // Same shape as the statement-position try test, but the `try`
    // hides inside a var-decl init.  Pre-phase-10 the sink wasn't
    // emitted in this position.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !void {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    const x = try sideEffect();
        \\    _ = x;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found_err_sink = false;
    for (cfg.blocks) |b| {
        var has_kill = false;
        var has_ret = false;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) has_kill = true;
            if (s.kind == .ret) has_ret = true;
        }
        if (has_kill and has_ret) found_err_sink = true;
    }
    try std.testing.expect(found_err_sink);
}

test "var-decl init `foo() catch BODY` forks: catch body's kill visible downstream" {
    // `const x = foo() catch { arena.deinit(); 0 };` — the catch
    // body's arena_kill must reach a non-entry block so the join at
    // the post-decl merge sees the kill on one incoming edge.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    const x = sideEffect() catch blk: {
        \\        arena.deinit();
        \\        break :blk 0;
        \\    };
        \\    _ = x;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var kill_in_non_entry = false;
    for (cfg.blocks, 0..) |b, i| {
        if (i == 0) continue;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) kill_in_non_entry = true;
        }
    }
    try std.testing.expect(kill_in_non_entry);
}

test "return position `return try foo()` adds error-exit sink with defer replayed" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !u32 {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    return try sideEffect();
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Two distinct blocks should each contain an arena_kill + ret:
    //   - the success-path return block (defer flushed inline)
    //   - the err-exit sink (errdefer + defer flushed)
    var sink_count: u32 = 0;
    for (cfg.blocks) |b| {
        var has_kill = false;
        var has_ret = false;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) has_kill = true;
            if (s.kind == .ret) has_ret = true;
        }
        if (has_kill and has_ret) sink_count += 1;
    }
    try std.testing.expect(sink_count >= 2);
}

test "return position `return foo() catch BODY` forks and merges into ret" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() u32 {
        \\    return sideEffect() catch 0;
        \\}
        \\pub fn sideEffect() !u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Catch fork: entry → catch_block + entry → merge; catch_block →
    // merge; merge contains the ret.  At least one block has ≥2
    // successors AND there exists a ret somewhere.
    var multi_succ = false;
    var has_ret_anywhere = false;
    for (cfg.blocks) |b| {
        if (b.successors.len >= 2) multi_succ = true;
        for (b.stmts) |s| {
            if (s.kind == .ret) has_ret_anywhere = true;
        }
    }
    try std.testing.expect(multi_succ);
    try std.testing.expect(has_ret_anywhere);
}

test "assign to known local emits .assign with classified rhs" {
    // `x = src;` — must emit .assign (not lowering_gap) so the analyzer
    // can update x's origin to copy_of(src).  Pre-phase-12 this was a
    // stubbed gap, conservatively collapsing both locals to .plain.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var x: u32 = 0;
        \\    var src: u32 = 1;
        \\    x = src;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found_assign_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                found_assign_copy_of = true;
            }
        }
    }
    try std.testing.expect(found_assign_copy_of);
}

test "assign rhs `try foo()` emits err-exit sink alongside .assign" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !void {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    var x: u32 = 0;
        \\    x = try sideEffect();
        \\    _ = x;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn sideEffect() !u32 { return 0; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found_err_sink = false;
    for (cfg.blocks) |b| {
        var has_kill = false;
        var has_ret = false;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) has_kill = true;
            if (s.kind == .ret) has_ret = true;
        }
        if (has_kill and has_ret) found_err_sink = true;
    }
    try std.testing.expect(found_err_sink);
}

test "assign to field (obj.x = src) emits .field_assign" {
    // Field assignment now goes through .field_assign so the
    // field's origin is tracked separately from the parent local.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var obj: Obj = .{ .x = 0 };
        \\    var src: u32 = 1;
        \\    obj.x = src;
        \\    return;
        \\}
        \\const Obj = struct { x: u32 };
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found_field_assign = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .field_assign and
                std.mem.eql(u8, s.kind.field_assign.name, "x"))
                found_field_assign = true;
        }
    }
    try std.testing.expect(found_field_assign);
}

test "break inside while adds edge from body to merge" {
    // Without phase 13, `break` fell through to lowering_gap and the
    // body just continued to its back-edge — the analyzer never saw a
    // direct body→merge edge that bypasses the header check.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    while (x) {
        \\        if (x) break;
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // The merge block exists.  Count how many blocks have an edge to
    // the merge block — pre-phase-13 it was 1 (header→merge only);
    // now it should be ≥2 (header→merge AND a body-side→merge).
    // We don't know merge's exact ID, so iterate: find blocks with
    // ≥2 successors targeting any non-header block, OR count edges
    // landing on each block and assert max ≥2 (header → merge AND
    // break-block → merge).
    var max_incoming: u32 = 0;
    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| {
            incoming[@intFromEnum(s)] += 1;
        }
    }
    for (incoming) |c| {
        if (c > max_incoming) max_incoming = c;
    }
    // Header gets ≥2 incoming (entry + body back-edge).  Merge gets
    // ≥2 now (header→merge + break-block→merge).  So we expect at
    // least TWO different blocks with ≥2 incoming edges.
    var ge2_count: u32 = 0;
    for (incoming) |c| if (c >= 2) {
        ge2_count += 1;
    };
    try std.testing.expect(ge2_count >= 2);
}

test "continue inside for adds back-edge from body-mid to header" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(xs: []const u32) void {
        \\    for (xs) |x| {
        \\        if (x == 0) continue;
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Header should have ≥3 incoming edges now: entry, body back-edge,
    // continue back-edge.  Pre-phase-13 it was 2.
    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| incoming[@intFromEnum(s)] += 1;
    }
    var max_in: u32 = 0;
    for (incoming) |c| if (c > max_in) {
        max_in = c;
    };
    try std.testing.expect(max_in >= 3);
}

test "break outside loop emits gap (defensive — Zig wouldn't compile)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    break;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap and
                std.mem.eql(u8, s.kind.lowering_gap.note, "break-outside-loop"))
                found = true;
        }
    }
    try std.testing.expect(found);
}

test "labeled break: `break :outer` from inner loop targets outer's merge" {
    // Without label resolution, inner break would just exit the inner
    // loop; outer's merge wouldn't get the extra incoming edge.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    outer: while (x) {
        \\        while (x) {
        \\            if (x) break :outer;
        \\        }
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Find the block reached by `break :outer` — it should be the
    // OUTER merge, which is downstream from outer header.  Heuristic:
    // there must exist a path of length 1 from some block (the break
    // emitter) directly to outer's merge, AND that merge must NOT be
    // the inner header.  Easier check: count blocks with ≥2 incoming
    // edges.  Pre-fix: outer header had 2 (entry + body); outer merge
    // had 1 (header→merge).  Post-fix: outer merge has 2 (header→merge
    // + labeled-break→merge).  So ≥2 blocks with ≥2 incoming.
    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| incoming[@intFromEnum(s)] += 1;
    }
    var ge2: u32 = 0;
    for (incoming) |c| if (c >= 2) {
        ge2 += 1;
    };
    // Outer header (≥2), inner header (≥2), outer merge (≥2 only with
    // the labeled-break fix).  Expect at least 3.
    try std.testing.expect(ge2 >= 3);
}

test "labeled continue: `continue :outer` from inner loop targets outer's header" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    outer: while (x) {
        \\        while (x) {
        \\            if (x) continue :outer;
        \\        }
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Outer header should now have ≥3 incoming: entry + inner-body
    // back-edge through outer body + labeled-continue back-edge.
    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| incoming[@intFromEnum(s)] += 1;
    }
    var max_in: u32 = 0;
    for (incoming) |c| if (c > max_in) {
        max_in = c;
    };
    try std.testing.expect(max_in >= 3);
}

test "labeled break to unknown label emits gap (not crash, no false match)" {
    // `break :nope;` inside a loop with no matching label — walks
    // the loop stack, finds nothing, must emit a gap rather than
    // accidentally targeting the innermost loop or crashing.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    while (x) {
        \\        if (x) break :nope;
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap and
                std.mem.eql(u8, s.kind.lowering_gap.note, "labeled-break-no-loop"))
                found = true;
        }
    }
    try std.testing.expect(found);
}

test "for-loop capture registered: use of `item` resolves to a tracked local" {
    // Pre-phase-15 `item` was an unknown identifier; the .assign rhs
    // would classify as .unknown.  After capture registration, `item`
    // is a known local and `x = item` should classify as copy_of.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(xs: []const u32) void {
        \\    var x: u32 = 0;
        \\    for (xs) |item| {
        \\        x = item;
        \\    }
        \\    _ = x;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                saw_copy_of = true;
            }
        }
    }
    try std.testing.expect(saw_copy_of);
}

test "for-loop multiple captures `|item, idx|` both registered" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(xs: []const u32) void {
        \\    var a: u32 = 0;
        \\    var b: usize = 0;
        \\    for (xs, 0..) |item, idx| {
        \\        a = item;
        \\        b = idx;
        \\    }
        \\    _ = a; _ = b;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var copy_of_count: u32 = 0;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                copy_of_count += 1;
            }
        }
    }
    // Both `a = item` and `b = idx` should classify as copy_of.
    try std.testing.expect(copy_of_count >= 2);
}

test "discard capture `|_|` is NOT registered as a local" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(xs: []const u32) void {
        \\    for (xs) |_| {}
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    for (cfg.locals) |l| {
        try std.testing.expect(!std.mem.eql(u8, l.name, "_"));
    }
}

test "while-with-payload `while (opt) |val|` registers capture" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(it: anytype) void {
        \\    var x: u32 = 0;
        \\    while (it.next()) |val| {
        \\        x = val;
        \\    }
        \\    _ = x;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                saw_copy_of = true;
            }
        }
    }
    try std.testing.expect(saw_copy_of);
}

test "if-optional payload `if (opt) |val|` registers capture" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(opt: ?u32) void {
        \\    var x: u32 = 0;
        \\    if (opt) |val| {
        \\        x = val;
        \\    }
        \\    _ = x;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                saw_copy_of = true;
            }
        }
    }
    try std.testing.expect(saw_copy_of);
}

test "if-error-union payload `else |err|` registers capture" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(r: anyerror!u32) void {
        \\    var e: anyerror = error.None;
        \\    if (r) |_| {} else |err| {
        \\        e = err;
        \\    }
        \\    _ = e;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                saw_copy_of = true;
            }
        }
    }
    try std.testing.expect(saw_copy_of);
}

test "switch case payload `.tag => |val|` registers capture" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\const U = union(enum) { a: u32, b: u32 };
        \\pub fn foo(u: U) void {
        \\    var x: u32 = 0;
        \\    switch (u) {
        \\        .a => |val| { x = val; },
        \\        .b => |val| { x = val; },
        \\    }
        \\    _ = x;
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var copy_of_count: u32 = 0;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                copy_of_count += 1;
            }
        }
    }
    try std.testing.expect(copy_of_count >= 2);
}

test "catch payload `catch |err|` registers capture (stmt position)" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var e: anyerror = error.None;
        \\    sideEffect() catch |err| { e = err; };
        \\    _ = e;
        \\    return;
        \\}
        \\pub fn sideEffect() !void {}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign and s.kind.assign.rhs_kind == .copy_of) {
                saw_copy_of = true;
            }
        }
    }
    try std.testing.expect(saw_copy_of);
}

test "statement-position labeled block: `break :blk` resolves to block merge" {
    // `blk: { ...; if (x) break :blk; ...; }` — the labeled break
    // must add an edge to the block's merge, not be a no-op gap.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    blk: {
        \\        if (x) break :blk;
        \\        // some non-trivial body so block isn't elided
        \\        var y: u32 = 0;
        \\        _ = y;
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // The block merge should have ≥2 incoming edges: the break path
    // AND the natural fallthrough from end-of-body.  Pre-phase-17
    // the break emitted a "labeled-break-no-loop" gap and no edge,
    // so merge had at most 1 incoming.
    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| incoming[@intFromEnum(s)] += 1;
    }
    var max_in: u32 = 0;
    for (incoming) |c| if (c > max_in) {
        max_in = c;
    };
    try std.testing.expect(max_in >= 2);

    // And NO labeled-break-no-loop gap should remain.
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap) {
                try std.testing.expect(!std.mem.eql(
                    u8,
                    s.kind.lowering_gap.note,
                    "labeled-break-no-loop",
                ));
            }
        }
    }
}

test "labeled block inside loop: break :blk doesn't escape the loop" {
    // `while (x) { blk: { ... break :blk; }; more; }` — break :blk
    // exits ONLY the block, not the loop.  Verify that the loop
    // merge isn't reached by the labeled break.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) void {
        \\    while (x) {
        \\        blk: {
        \\            if (x) break :blk;
        \\            var y: u32 = 0;
        \\            _ = y;
        \\        }
        \\        // this stmt is reachable from the block break.
        \\        var z: u32 = 0;
        \\        _ = z;
        \\    }
        \\    return;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Confirm we built a non-trivial CFG and there's no leftover
    // labeled-break-no-loop gap.
    try std.testing.expect(cfg.blocks.len >= 5);
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap) {
                try std.testing.expect(!std.mem.eql(
                    u8,
                    s.kind.lowering_gap.note,
                    "labeled-break-no-loop",
                ));
            }
        }
    }
}

test "expression-position labeled block: var-decl init `const x = blk: {...}` lowers body" {
    // Side effect inside the labeled-block init (arena.deinit() here)
    // must reach a CFG block — pre-phase-18 the init was opaque, so
    // the deinit call was invisible to the analyzer.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    const r = blk: {
        \\        arena.deinit();
        \\        break :blk 0;
        \\    };
        \\    _ = r;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_kill = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) saw_kill = true;
        }
    }
    try std.testing.expect(saw_kill);
}

test "expression-position labeled block: return `return blk: {...}` lowers body" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() u32 {
        \\    var arena = Arena.init(0);
        \\    return blk: {
        \\        arena.deinit();
        \\        break :blk 0;
        \\    };
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_kill = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) saw_kill = true;
        }
    }
    try std.testing.expect(saw_kill);
}

test "expression-position labeled block: `break :blk val` adds edge to merge" {
    // The block has two exit edges — `break :blk 1` and natural
    // fallthrough.  Merge should have ≥2 incoming.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo(x: bool) u32 {
        \\    const r = blk: {
        \\        if (x) break :blk 1;
        \\        break :blk 0;
        \\    };
        \\    return r;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var incoming = try gpa.alloc(u32, cfg.blocks.len);
    defer gpa.free(incoming);
    @memset(incoming, 0);
    for (cfg.blocks) |b| {
        for (b.successors) |s| incoming[@intFromEnum(s)] += 1;
    }
    var max_in: u32 = 0;
    for (incoming) |c| if (c > max_in) {
        max_in = c;
    };
    try std.testing.expect(max_in >= 2);
    // No leftover labeled-break-no-loop gaps.
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap) {
                try std.testing.expect(!std.mem.eql(
                    u8,
                    s.kind.lowering_gap.note,
                    "labeled-break-no-loop",
                ));
            }
        }
    }
}

test "expression-position labeled block: assign `x = blk: {...}` lowers body" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var arena = Arena.init(0);
        \\    var x: u32 = 0;
        \\    x = blk: {
        \\        arena.deinit();
        \\        break :blk 1;
        \\    };
        \\    _ = x;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var saw_kill = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) saw_kill = true;
        }
    }
    try std.testing.expect(saw_kill);
}

test "destructuring var-decl `const a, const b = pair()` registers both locals" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    const a, const b = pair();
        \\    _ = a; _ = b;
        \\    return;
        \\}
        \\pub fn pair() struct { u32, u32 } { return .{ 0, 1 }; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // TestBundle now owns src_z (phase 20 fix) — name slices stay
    // valid until result.deinit, so we can assert on names directly.
    var saw_a = false;
    var saw_b = false;
    for (cfg.locals) |l| {
        if (std.mem.eql(u8, l.name, "a")) saw_a = true;
        if (std.mem.eql(u8, l.name, "b")) saw_b = true;
    }
    try std.testing.expect(saw_a and saw_b);

    var decl_count: u32 = 0;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .decl) decl_count += 1;
        }
    }
    try std.testing.expect(decl_count >= 2);
}

test "name slices live for the test bundle's lifetime (phase 20 dangle fix)" {
    // Regression guard for the parseAndLower → src_z dangle bug.
    // Pre-phase-20, this assertion saw garbage UTF-8 because the
    // helper freed src_z on return.  If TestBundle ever loses its
    // src_z ownership, this will start printing `name=�...` again.
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var unique_local_name_xyz: u32 = 0;
        \\    _ = unique_local_name_xyz;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found = false;
    for (cfg.locals) |l| {
        if (std.mem.eql(u8, l.name, "unique_local_name_xyz")) found = true;
    }
    try std.testing.expect(found);
}

test "destructuring assign `a, b = pair()` emits .assign for each target" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() void {
        \\    var a: u32 = 0;
        \\    var b: u32 = 0;
        \\    a, b = pair();
        \\    _ = a; _ = b;
        \\    return;
        \\}
        \\pub fn pair() struct { u32, u32 } { return .{ 0, 1 }; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var assign_count: u32 = 0;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .assign) assign_count += 1;
        }
    }
    // At least 2 from the destructure (could be more from the initial
    // `var a: u32 = 0` decls, but those are .decl not .assign).
    try std.testing.expect(assign_count >= 2);

    // No leftover assign_destructure gap.
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .lowering_gap) {
                try std.testing.expect(!std.mem.eql(
                    u8,
                    s.kind.lowering_gap.note,
                    "assign_destructure",
                ));
            }
        }
    }
}

test "destructure rhs `try pair()` adds err-exit sink" {
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() !void {
        \\    var arena = Arena.init(0);
        \\    defer arena.deinit();
        \\    const a, const b = try pair();
        \\    _ = a; _ = b;
        \\    return;
        \\}
        \\const Arena = struct {
        \\    pub fn init(_: u32) Arena { return .{}; }
        \\    pub fn deinit(_: *Arena) void {}
        \\};
        \\pub fn pair() !struct { u32, u32 } { return .{ 0, 1 }; }
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    var found_err_sink = false;
    for (cfg.blocks) |b| {
        var has_kill = false;
        var has_ret = false;
        for (b.stmts) |s| {
            if (s.kind == .arena_kill) has_kill = true;
            if (s.kind == .ret) has_ret = true;
        }
        if (has_kill and has_ret) found_err_sink = true;
    }
    try std.testing.expect(found_err_sink);
}

test "try unwraps inner expression: copy_of(src) preserved through try" {
    // `const y = try src;` — y's origin should be copy_of(src), not
    // .unknown.  Validates classifyExpr's .@\"try\" recursion.
    // (Use a local — fn params aren't registered in name_to_local.)
    const gpa = std.testing.allocator;
    var result = try parseAndLower(gpa,
        \\pub fn foo() anyerror!u32 {
        \\    const src: anyerror!u32 = 1;
        \\    const y = try src;
        \\    return y;
        \\}
        \\
    );
    defer result.deinit(gpa);
    const cfg = result.cfg.?;

    // Find the decl for `y` and assert its init_kind is .copy_of.
    var found_copy_of = false;
    for (cfg.blocks) |b| {
        for (b.stmts) |s| {
            if (s.kind == .decl and s.kind.decl.init_kind == .copy_of) {
                found_copy_of = true;
            }
        }
    }
    try std.testing.expect(found_copy_of);
}
