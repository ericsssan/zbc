//! Per-file semantic model.
//!
//! Built ONCE per `Ast` (typically per file).  Rules ask the model
//! questions instead of re-walking the token stream to answer them:
//!
//!   - "Does this file declare a struct named `Outer`?"
//!     → `model.findType(\"Outer\")`
//!   - "Does `Outer` have a method called `deinit`?"
//!     → `outer.hasMethod(\"deinit\")` or `outer.findMethod(\"deinit\")`
//!   - "What fields does `Outer` have?  What are their types?"
//!     → `outer.fields`
//!   - "What top-level fns exist?  Which are methods of which type?"
//!     → `model.fns`, each with `enclosing_type`
//!
//! Three rules currently re-build a private version of this every
//! call: `missing_deinit_on_composed_owner` (struct-deinit table),
//! `asymmetric_field_free` (struct-field+free-pair table), and
//! `reset_skips_pooled_resource_release` (struct + method body
//! ranges).  After this lands they share one cache.
//!
//! Approach: token-level scan, NOT a recursive Ast.Node walk.  Why:
//!   - The four `container_decl*` AST tag variants are awkward to
//!     dispatch over; token-walking sidesteps them.
//!   - All current rules already token-walk; the model matches
//!     their idiom so they keep using `TokenIndex` for spans.
//!   - The "find struct decl + walk its body" pattern is well-
//!     tested across the existing rules; we're just centralizing it.
//!
//! Scope (v1):
//!   - Top-level `const Name = struct/union/enum { ... }` decls
//!   - Methods inside those decls
//!   - Fields inside structs (best-effort, identifier `: type,` shape)
//!   - Top-level `fn name(...)` decls (NOT methods — those live in
//!     types[].methods)
//!
//! Out of scope (v1):
//!   - Nested types (struct inside struct).  Add when a rule needs it.
//!   - Anonymous types (`return struct { ... }`).  Add when needed.
//!   - extern fns / extern structs.
//!   - Inheritance via `usingnamespace` (deprecated anyway).

const std = @import("std");
const Ast = std.zig.Ast;

const lexer = @import("lexer.zig");

pub const TokenIndex = lexer.TokenIndex;
const TokenTag = lexer.TokenTag;

pub const TypeKind = enum { struct_, union_, enum_, opaque_ };

pub const FieldInfo = struct {
    /// The field's identifier slice (borrowed from `tree`).
    name: []const u8,
    /// Token index of the identifier.
    name_token: TokenIndex,
    /// First token of the type expression (after `:`).
    type_first: TokenIndex,
    /// Last token of the type expression (before `=` default or `,`).
    type_last: TokenIndex,
    /// True if the field has a `= <default>` initializer.
    has_default: bool,
};

pub const Receiver = struct {
    /// Parameter name — usually "self", "this", but could be
    /// anything (e.g. "inspector").
    name: []const u8,
    name_token: TokenIndex,
    /// True if the receiver is `*Self` / `*Name` (vs `Self` / `Name`).
    is_ptr: bool,
    /// True if `*const Self` (only meaningful when `is_ptr`).
    is_const: bool,
};

pub const MethodInfo = struct {
    /// Method name (borrowed from `tree`).
    name: []const u8,
    name_token: TokenIndex,
    /// The fn_decl AST node.
    fn_decl: Ast.Node.Index,
    /// The body AST node (block_*).
    body: Ast.Node.Index,
    /// First token of the body (`{`).
    body_first: TokenIndex,
    /// Last token of the body (`}`).
    body_last: TokenIndex,
    /// True if declared `pub fn ...`.
    is_pub: bool,
    /// The first parameter, if it looks like a method receiver
    /// (named `self`/`this` OR typed as `Self`/`*Self`/the
    /// enclosing type name).  null for "static" methods.
    receiver: ?Receiver,
};

pub const TypeInfo = struct {
    /// Type's declared name (`const Name = struct { ... }` → "Name").
    name: []const u8,
    /// Token index of the name (the `Name` identifier).
    name_token: TokenIndex,
    /// struct / union / enum / opaque.
    kind: TypeKind,
    /// Token index of the body's opening `{`.
    body_first: TokenIndex,
    /// Token index of the body's closing `}`.
    body_last: TokenIndex,
    /// All struct-level fields (best-effort identifier-colon detection).
    /// Empty for enum / opaque.
    fields: []const FieldInfo,
    /// All `fn name(...)` declarations inside the body.
    methods: []const MethodInfo,
    /// Index into FileModel.types of the enclosing type, if this is
    /// a nested type declaration (`const Outer = struct { const Inner
    /// = struct { ... }; };`).  null for top-level types.
    parent: ?u32 = null,

    pub fn hasMethod(self: TypeInfo, name: []const u8) bool {
        return self.findMethod(name) != null;
    }

    pub fn findMethod(self: TypeInfo, name: []const u8) ?*const MethodInfo {
        for (self.methods) |*m| {
            if (std.mem.eql(u8, m.name, name)) return m;
        }
        return null;
    }

    /// True iff the type has any cleanup method (deinit/close/
    /// destroy/free/stop/finalize/dispose) — the canonical
    /// "this type owns something that needs releasing" signal.
    pub fn hasCleanupMethod(self: TypeInfo) bool {
        return self.hasMethod("deinit") or
            self.hasMethod("close") or
            self.hasMethod("destroy") or
            self.hasMethod("free") or
            self.hasMethod("stop") or
            self.hasMethod("finalize") or
            self.hasMethod("dispose");
    }

    pub fn findField(self: TypeInfo, name: []const u8) ?*const FieldInfo {
        for (self.fields) |*f| {
            if (std.mem.eql(u8, f.name, name)) return f;
        }
        return null;
    }
};

pub const FnInfo = struct {
    name: []const u8,
    name_token: TokenIndex,
    fn_decl: Ast.Node.Index,
    body: Ast.Node.Index,
    body_first: TokenIndex,
    body_last: TokenIndex,
    is_pub: bool,
    returns_error_union: bool,
};

pub const FileModel = struct {
    /// All allocations live here.  `deinit` drops everything at once.
    arena: std.heap.ArenaAllocator,
    tree: *const Ast,
    /// All top-level struct/union/enum declarations.
    types: []const TypeInfo,
    /// All top-level fn_decl nodes.  Methods live in `types[].methods`,
    /// NOT here.
    fns: []const FnInfo,

    pub fn deinit(self: *FileModel) void {
        self.arena.deinit();
    }

    /// Find a type by name (linear scan; types lists are small per file).
    pub fn findType(self: *const FileModel, name: []const u8) ?*const TypeInfo {
        for (self.types) |*t| {
            if (std.mem.eql(u8, t.name, name)) return t;
        }
        return null;
    }

    /// Convenience: type exists AND has the named method.
    pub fn typeHasMethod(self: *const FileModel, type_name: []const u8, method_name: []const u8) bool {
        const ti = self.findType(type_name) orelse return false;
        return ti.hasMethod(method_name);
    }

    /// Find a top-level fn by name.
    pub fn findFn(self: *const FileModel, name: []const u8) ?*const FnInfo {
        for (self.fns) |*f| {
            if (std.mem.eql(u8, f.name, name)) return f;
        }
        return null;
    }

    /// True iff the file declares a type with this name.
    pub fn hasType(self: *const FileModel, name: []const u8) bool {
        return self.findType(name) != null;
    }

    /// Find the type whose body contains `fn_decl`.  Returns null
    /// for top-level fns.  When `fn_decl` is inside a nested type,
    /// returns the INNERMOST enclosing type (smallest body range),
    /// not the outer — methods on nested types should associate
    /// with their declaring type, not its container.
    pub fn containingTypeOf(self: *const FileModel, fn_decl: Ast.Node.Index) ?*const TypeInfo {
        const fn_tok = self.tree.firstToken(fn_decl);
        var best: ?*const TypeInfo = null;
        var best_span: u32 = std.math.maxInt(u32);
        for (self.types) |*ti| {
            if (fn_tok > ti.body_first and fn_tok < ti.body_last) {
                const span = ti.body_last - ti.body_first;
                if (span < best_span) {
                    best = ti;
                    best_span = span;
                }
            }
        }
        return best;
    }

    /// (struct_name, field_name) -> the field's declared base type
    /// name with `*` / `?` / `const` / `[]` wrappers stripped.
    /// Returns null when the struct or field isn't known, or when the
    /// type has no resolvable base name (slice/array/fn-pointer
    /// shapes).  Matches the old `Db.fieldType` query shape.
    pub fn fieldType(self: *const FileModel, struct_name: []const u8, field_name: []const u8) ?[]const u8 {
        const ti = self.findType(struct_name) orelse return null;
        const f = ti.findField(field_name) orelse return null;
        return baseTypeName(self.tree, f.type_first, f.type_last);
    }

    /// True iff the field's declared type starts with `*` (after
    /// stripping `?` / `const`).  Heuristic for "this field is a
    /// borrow, not an owned value" — pointer-typed struct fields
    /// almost always alias storage that lives elsewhere.  Inference
    /// replacement for the old `Db.isBorrowedField` query that
    /// previously relied on `/// @borrowed` doc-comment annotations.
    pub fn fieldIsPointer(self: *const FileModel, struct_name: []const u8, field_name: []const u8) bool {
        const ti = self.findType(struct_name) orelse return false;
        const f = ti.findField(field_name) orelse return false;
        const tags = self.tree.tokens.items(.tag);
        var t: TokenIndex = f.type_first;
        while (t <= f.type_last) : (t += 1) {
            switch (tags[t]) {
                .question_mark, .keyword_const => {},
                .asterisk => return true,
                else => return false,
            }
        }
        return false;
    }

    /// True iff `struct_name`.`field_name` is the heap-owning half of
    /// a flag-paired ownership pattern: a sibling field
    /// `<field_name>_allocated: bool` exists on the same struct.
    /// Inference-equivalent of the old `Db.flag_owned_fields` set —
    /// pure syntactic pairing, no annotation needed.
    pub fn isFlagOwnedField(self: *const FileModel, struct_name: []const u8, field_name: []const u8) bool {
        const ti = self.findType(struct_name) orelse return false;
        if (ti.findField(field_name) == null) return false;
        // Look for the sibling `<field>_allocated: bool` field.
        var buf: [128]u8 = undefined;
        const suffix = "_allocated";
        if (field_name.len + suffix.len > buf.len) return false;
        @memcpy(buf[0..field_name.len], field_name);
        @memcpy(buf[field_name.len..][0..suffix.len], suffix);
        const sibling_name = buf[0 .. field_name.len + suffix.len];
        const sibling = ti.findField(sibling_name) orelse return false;
        // Sibling type must be exactly `bool`.
        if (sibling.type_first != sibling.type_last) return false;
        return std.mem.eql(u8, self.tree.tokenSlice(sibling.type_first), "bool");
    }

    /// Iterate over `(field_name)` pairs of every flag-owned field
    /// on `struct_name`.  Caller-owned slice; freed by `gpa.free`.
    pub fn flagOwnedFields(
        self: *const FileModel,
        gpa: std.mem.Allocator,
        struct_name: []const u8,
    ) ![]const []const u8 {
        const ti = self.findType(struct_name) orelse return &.{};
        var out: std.ArrayListUnmanaged([]const u8) = .empty;
        for (ti.fields) |f| {
            if (self.isFlagOwnedField(struct_name, f.name)) {
                try out.append(gpa, f.name);
            }
        }
        return out.toOwnedSlice(gpa);
    }
};

/// True iff `name_tok` is nested inside ANY `fn ... { ... }` body
/// in the source — even one enclosing nested struct/union/enum
/// decls.  Walks backward through every unmatched `{`; at each one,
/// looks back for the keyword that opens the brace (`fn` -> fn body,
/// `struct`/`union`/`enum` -> type body).  Returns true on the
/// first `fn` brace found, false if we reach the file top without
/// hitting one.
///
/// Used to filter out methods of structs returned from generic fns
/// (e.g. `fn Wrap(T) type { return struct { fn deinit(...) {} }; }`)
/// from model.fns — those bodies live inside a fn's source range
/// and would otherwise look top-level by syntactic walk.
fn isInsideFnBody(tree: *const Ast, name_tok: TokenIndex) bool {
    const tags = tree.tokens.items(.tag);
    if (name_tok == 0) return false;
    var t: i64 = @as(i64, @intCast(name_tok)) - 1;
    var depth: i32 = 0;
    while (t >= 0) : (t -= 1) {
        const tok: TokenIndex = @intCast(t);
        switch (tags[tok]) {
            .r_brace => depth += 1,
            .l_brace => {
                if (depth == 0) {
                    // Unmatched `{`.  Identify what opened it.
                    switch (braceOpenerKind(tags, tok)) {
                        .fn_body => return true,
                        .type_body => {
                            // Struct/union/enum body — continue
                            // walking outward past it.  depth stays
                            // 0 (we're now in the enclosing scope).
                        },
                        .unknown => return false,
                    }
                } else {
                    depth -= 1;
                }
            },
            else => {},
        }
    }
    return false;
}

const BraceOpener = enum { fn_body, type_body, unknown };

/// Classify what kind of construct opens the `{` at `brace_tok`.
/// Looks back past parens/type-expressions for the introducing
/// keyword.  Conservative: returns `.unknown` rather than guessing
/// when the lookback hits a terminator or runs out of budget.
fn braceOpenerKind(tags: []const std.zig.Token.Tag, brace_tok: TokenIndex) BraceOpener {
    if (brace_tok == 0) return .unknown;
    var u: i64 = @as(i64, @intCast(brace_tok)) - 1;
    var paren: i32 = 0;
    var hops: u32 = 0;
    while (u >= 0 and hops < 128) : ({
        u -= 1;
        hops += 1;
    }) {
        const ut: TokenIndex = @intCast(u);
        switch (tags[ut]) {
            .r_paren => paren += 1,
            .l_paren => paren -= 1,
            .keyword_fn => if (paren == 0) return .fn_body,
            .keyword_struct, .keyword_union, .keyword_enum, .keyword_opaque => {
                if (paren == 0) return .type_body;
            },
            // Block / stmt terminators break the lookback.
            .l_brace, .r_brace, .semicolon => if (paren == 0) return .unknown,
            else => {},
        }
    }
    return .unknown;
}

/// Strip pointer / optional / const / slice wrappers from a type
/// expression token range and return the base identifier.  Returns
/// null when the base isn't a single identifier (fn-pointer, anon
/// struct, etc.).
fn baseTypeName(tree: *const Ast, first: TokenIndex, last: TokenIndex) ?[]const u8 {
    const tags = tree.tokens.items(.tag);
    var t: TokenIndex = first;
    while (t <= last) : (t += 1) {
        switch (tags[t]) {
            // Strip leading wrappers and keep scanning.
            .asterisk, .question_mark, .keyword_const, .keyword_var, .l_bracket, .r_bracket => {},
            .identifier => return tree.tokenSlice(t),
            // Anything else (paren, dot, etc.) — give up.
            else => return null,
        }
    }
    return null;
}

/// Build a FileModel for the given Ast.  `tree` must outlive the model.
pub fn build(gpa: std.mem.Allocator, tree: *const Ast) !FileModel {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var types: std.ArrayListUnmanaged(TypeInfo) = .empty;
    var fns: std.ArrayListUnmanaged(FnInfo) = .empty;

    const tags = tree.tokens.items(.tag);
    const tok_count: u32 = @intCast(tree.tokens.len);
    if (tok_count == 0) {
        return .{
            .arena = arena,
            .tree = tree,
            .types = &.{},
            .fns = &.{},
        };
    }
    const last: TokenIndex = tok_count - 1;

    // ── Pass 1: top-level type decls ───────────────────────
    // Walks file tokens for `[pub] const Name = struct/union/enum {
    // ... };` at brace-depth 0; recurses into each collected type's
    // body to pick up nested type declarations (`const Inner = struct
    // { ... }` inside an outer struct's body).  Nested entries land in
    // the same flat `types` list with `parent` set to the outer's
    // index.
    try collectTypesInRange(a, tree, &types, 0, last, null);

    // ── Pass 2: top-level fn decls ─────────────────────────
    // Walk Ast.fn_decl nodes; classify as top-level by checking that
    // their containing token is NOT inside any type body we just
    // collected.
    var idx: u32 = 1;
    while (idx < tree.nodes.len) : (idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var proto_buf: [1]Ast.Node.Index = undefined;
        const proto = lexer.fnProto(tree, &proto_buf, node) orelse continue;
        const name_tok = proto.name_token orelse continue;
        const body = lexer.bodyOf(tree, node) orelse continue;

        // Skip if inside a type body.
        var inside_type = false;
        for (types.items) |ti| {
            if (name_tok > ti.body_first and name_tok < ti.body_last) {
                inside_type = true;
                break;
            }
        }
        if (inside_type) continue;

        // Skip if inside ANY fn's body (i.e., this is a nested fn /
        // a method on a struct declared inside `fn X() type { return
        // struct { ... }; }`).  Without this filter, methods of
        // generic-fn-returned structs leak into model.fns as
        // pseudo-top-level entries — summaryByName then finds them
        // and applies their inferred takes to unrelated call sites.
        if (isInsideFnBody(tree, name_tok)) continue;

        try fns.append(a, .{
            .name = tree.tokenSlice(name_tok),
            .name_token = name_tok,
            .fn_decl = node,
            .body = body,
            .body_first = tree.firstToken(body),
            .body_last = tree.lastToken(body),
            .is_pub = isPrecededByPub(tags, name_tok),
            .returns_error_union = protoReturnsErrorUnion(tree, proto),
        });
    }

    return .{
        .arena = arena,
        .tree = tree,
        .types = try types.toOwnedSlice(a),
        .fns = try fns.toOwnedSlice(a),
    };
}

// ── Internal: type, field, method extraction ──────────────

/// Collect every `const Name = struct/union/enum/opaque { ... }`
/// decl in `[start, end]` at brace-depth 0 (relative to `start`),
/// then recurse into each collected type's body to pick up nested
/// type decls.  All collected types share the same flat `types`
/// list; nested entries carry `parent` = the index of the enclosing
/// type at append time.
fn collectTypesInRange(
    a: std.mem.Allocator,
    tree: *const Ast,
    types: *std.ArrayListUnmanaged(TypeInfo),
    start: TokenIndex,
    end: TokenIndex,
    parent: ?u32,
) std.mem.Allocator.Error!void {
    const tags = tree.tokens.items(.tag);
    if (end < 4 or start + 4 >= end) return;

    var depth: u32 = 0;
    var t: TokenIndex = start;
    while (t + 4 < end) : (t += 1) {
        switch (tags[t]) {
            .l_brace, .l_paren, .l_bracket => {
                depth += 1;
                continue;
            },
            .r_brace, .r_paren, .r_bracket => {
                if (depth > 0) depth -= 1;
                continue;
            },
            else => {},
        }
        if (depth != 0) continue;
        if (tags[t] != .keyword_const) continue;
        if (tags[t + 1] != .identifier) continue;
        var eq: TokenIndex = t + 2;
        while (eq < end and tags[eq] != .equal and tags[eq] != .semicolon) : (eq += 1) {}
        if (eq >= end or tags[eq] != .equal) continue;
        if (eq + 2 > end) continue;
        var k: TokenIndex = eq + 1;
        if (tags[k] == .keyword_extern or tags[k] == .keyword_packed) k += 1;
        if (k + 1 > end) continue;
        const kind: TypeKind = switch (tags[k]) {
            .keyword_struct => .struct_,
            .keyword_union => .union_,
            .keyword_enum => .enum_,
            .keyword_opaque => .opaque_,
            else => continue,
        };
        var b: TokenIndex = k + 1;
        if (b <= end and tags[b] == .l_paren) {
            const cp = lexer.matchParen(tags, b, end) orelse continue;
            b = cp + 1;
        }
        if (b > end or tags[b] != .l_brace) continue;
        const body_last = lexer.matchBrace(tags, b, end) orelse continue;

        const fields_slice = if (kind == .struct_)
            try collectFields(a, tree, b + 1, body_last - 1)
        else
            &[_]FieldInfo{};
        const methods_slice = try collectMethods(a, tree, b + 1, body_last - 1, tree.tokenSlice(t + 1));

        const this_index: u32 = @intCast(types.items.len);
        try types.append(a, .{
            .name = tree.tokenSlice(t + 1),
            .name_token = t + 1,
            .kind = kind,
            .body_first = b,
            .body_last = body_last,
            .fields = fields_slice,
            .methods = methods_slice,
            .parent = parent,
        });

        // Recurse into THIS type's body to collect any nested type
        // decls.  `b + 1` skips the opening `{`; `body_last - 1`
        // stops before the closing `}`.
        if (body_last > b + 1) {
            try collectTypesInRange(a, tree, types, b + 1, body_last - 1, this_index);
        }

        // Skip past the body so the outer scan doesn't re-enter it.
        t = body_last;
    }
}

fn collectFields(
    a: std.mem.Allocator,
    tree: *const Ast,
    start: TokenIndex,
    end: TokenIndex,
) ![]const FieldInfo {
    var out: std.ArrayListUnmanaged(FieldInfo) = .empty;
    const tags = tree.tokens.items(.tag);
    if (start > end) return try out.toOwnedSlice(a);

    var t: TokenIndex = start;
    while (t <= end) : (t += 1) {
        // Skip nested braces (fn bodies, anon struct types).
        if (tags[t] == .l_brace) {
            const close = lexer.matchBrace(tags, t, end) orelse break;
            t = close;
            continue;
        }
        // Skip fn declarations (proto + body).
        if (tags[t] == .keyword_fn) {
            t = lexer.skipNestedFnProtoAndBody(tags, t, end);
            continue;
        }
        // Skip nested decls — `[pub] const/var Name ...;` — the
        // entire statement, terminator inclusive.  Without this we'd
        // misread `pub const empty: T = ...` as a field named `empty`.
        if (tags[t] == .keyword_pub or tags[t] == .keyword_const or
            tags[t] == .keyword_var or tags[t] == .keyword_comptime or
            tags[t] == .keyword_threadlocal)
        {
            const sc = lexer.findStmtSemicolon(tags, t, end) orelse break;
            t = sc;
            continue;
        }
        // Field shape: `<identifier>: <type-tokens>(= <default>)?,`
        if (tags[t] != .identifier) continue;
        if (t + 1 > end or tags[t + 1] != .colon) continue;
        // Walk the type expression until `=` (default) or `,` (terminator).
        const type_first: TokenIndex = t + 2;
        var type_last: TokenIndex = type_first;
        var d: u32 = 0;
        var has_default = false;
        var u: TokenIndex = type_first;
        while (u <= end) : (u += 1) {
            switch (tags[u]) {
                .l_paren, .l_brace, .l_bracket => d += 1,
                .r_paren, .r_brace, .r_bracket => if (d > 0) {
                    d -= 1;
                } else break,
                .equal => if (d == 0) {
                    has_default = true;
                    break;
                },
                .comma => if (d == 0) break,
                else => {},
            }
            type_last = u;
        }
        try out.append(a, .{
            .name = tree.tokenSlice(t),
            .name_token = t,
            .type_first = type_first,
            .type_last = type_last,
            .has_default = has_default,
        });
        // Advance past this field's terminator.
        if (u <= end and tags[u] == .equal) {
            // Skip default expression to the next `,` at depth 0.
            var dd: u32 = 0;
            while (u <= end) : (u += 1) {
                switch (tags[u]) {
                    .l_paren, .l_brace, .l_bracket => dd += 1,
                    .r_paren, .r_brace, .r_bracket => if (dd > 0) {
                        dd -= 1;
                    },
                    .comma => if (dd == 0) break,
                    else => {},
                }
            }
        }
        t = u;
    }
    return try out.toOwnedSlice(a);
}

fn collectMethods(
    a: std.mem.Allocator,
    tree: *const Ast,
    start: TokenIndex,
    end: TokenIndex,
    enclosing_type_name: []const u8,
) ![]const MethodInfo {
    var out: std.ArrayListUnmanaged(MethodInfo) = .empty;
    const tags = tree.tokens.items(.tag);
    if (start > end) return try out.toOwnedSlice(a);

    // Walk fn_decl nodes whose proto's name token is in [start, end]
    // AND not inside a nested brace within [start, end].
    var idx: u32 = 1;
    while (idx < tree.nodes.len) : (idx += 1) {
        const node: Ast.Node.Index = @enumFromInt(idx);
        if (tree.nodeTag(node) != .fn_decl) continue;
        var proto_buf: [1]Ast.Node.Index = undefined;
        const proto = lexer.fnProto(tree, &proto_buf, node) orelse continue;
        const name_tok = proto.name_token orelse continue;
        if (name_tok < start or name_tok > end) continue;
        // Reject if inside a nested type body (depth > 0 at name_tok).
        if (isInsideNestedBrace(tags, start, end, name_tok)) continue;
        const body = lexer.bodyOf(tree, node) orelse continue;

        try out.append(a, .{
            .name = tree.tokenSlice(name_tok),
            .name_token = name_tok,
            .fn_decl = node,
            .body = body,
            .body_first = tree.firstToken(body),
            .body_last = tree.lastToken(body),
            .is_pub = isPrecededByPub(tags, name_tok),
            .receiver = extractReceiver(tree, proto, enclosing_type_name),
        });
    }
    return try out.toOwnedSlice(a);
}

/// True if `tok` is inside a `{...}` block nested within `[start, end]`
/// (i.e., the depth at `tok` measured from `start` is > 0).
fn isInsideNestedBrace(
    tags: []const TokenTag,
    start: TokenIndex,
    end: TokenIndex,
    tok: TokenIndex,
) bool {
    var depth: u32 = 0;
    var t: TokenIndex = start;
    while (t <= end and t <= tok) : (t += 1) {
        if (t == tok) return depth > 0;
        switch (tags[t]) {
            .l_brace => depth += 1,
            .r_brace => if (depth > 0) {
                depth -= 1;
            },
            else => {},
        }
    }
    return false;
}

/// `pub` directly before `fn name` — checked at `name_token - 2`
/// (the `fn` keyword is at `name_token - 1`).
fn isPrecededByPub(tags: []const TokenTag, name_token: TokenIndex) bool {
    if (name_token < 2) return false;
    if (tags[name_token - 1] != .keyword_fn) return false;
    return tags[name_token - 2] == .keyword_pub;
}

fn extractReceiver(
    tree: *const Ast,
    proto: Ast.full.FnProto,
    enclosing_type_name: []const u8,
) ?Receiver {
    var it = proto.iterate(tree);
    const first = it.next() orelse return null;
    const name_tok = first.name_token orelse return null;
    const name = tree.tokenSlice(name_tok);
    const tags = tree.tokens.items(.tag);
    // Find the type tokens — they start after the parameter name's `:`.
    if (name_tok + 1 >= tree.tokens.len) return null;
    if (tags[name_tok + 1] != .colon) return null;
    var t = name_tok + 2;
    const type_first = t;
    var is_ptr = false;
    var is_const = false;
    if (t < tree.tokens.len and tags[t] == .asterisk) {
        is_ptr = true;
        t += 1;
        if (t < tree.tokens.len and tags[t] == .keyword_const) {
            is_const = true;
            t += 1;
        }
    }
    // The type should be `Self` or the enclosing type name, OR
    // the parameter should be named self/this.  Otherwise we can't
    // confidently call this a receiver — return null.
    const is_self_or_this = std.mem.eql(u8, name, "self") or std.mem.eql(u8, name, "this");
    if (t < tree.tokens.len and tags[t] == .identifier) {
        const tname = tree.tokenSlice(t);
        if (std.mem.eql(u8, tname, "Self") or std.mem.eql(u8, tname, enclosing_type_name)) {
            return .{
                .name = name,
                .name_token = name_tok,
                .is_ptr = is_ptr,
                .is_const = is_const,
            };
        }
    }
    if (is_self_or_this) {
        return .{
            .name = name,
            .name_token = name_tok,
            .is_ptr = is_ptr,
            .is_const = is_const,
        };
    }
    _ = type_first;
    return null;
}

fn protoReturnsErrorUnion(tree: *const Ast, proto: Ast.full.FnProto) bool {
    const rt = proto.ast.return_type.unwrap() orelse return false;
    const tags = tree.tokens.items(.tag);
    const first = tree.firstToken(rt);
    // `!T` — the `!` is the token IMMEDIATELY before the return-type
    // AST node's first token (the AST stores just `T` as the return type).
    // Also handles `E!T` (e.g. `error{Foo}!void`) where the bang is
    // somewhere inside the span; checking `first - 1` is enough for
    // the common `!T` form, and the explicit-error form has a `!`
    // inside the type's token range.
    if (first > 0 and tags[first - 1] == .bang) return true;
    const last_rt = tree.lastToken(rt);
    return lexer.hasTokenInRange(tags, first, last_rt, .bang);
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

test "build: single struct with deinit + field" {
    const src: [:0]const u8 =
        \\const Outer = struct {
        \\    inner: Inner,
        \\    count: u32 = 0,
        \\    pub fn deinit(self: *Outer) void {
        \\        _ = self;
        \\    }
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    try testing.expectEqual(@as(usize, 1), model.types.len);
    const ti = &model.types[0];
    try testing.expectEqualStrings("Outer", ti.name);
    try testing.expectEqual(TypeKind.struct_, ti.kind);
    try testing.expectEqual(@as(usize, 2), ti.fields.len);
    try testing.expectEqualStrings("inner", ti.fields[0].name);
    try testing.expectEqualStrings("count", ti.fields[1].name);
    try testing.expect(!ti.fields[0].has_default);
    try testing.expect(ti.fields[1].has_default);
    try testing.expect(ti.hasMethod("deinit"));
    try testing.expect(!ti.hasMethod("init"));
    try testing.expect(ti.hasCleanupMethod());
}

test "build: two structs in one file, type lookup" {
    const src: [:0]const u8 =
        \\const Inner = struct {
        \\    x: u32,
        \\    pub fn deinit(self: *Inner) void { _ = self; }
        \\};
        \\const Outer = struct {
        \\    inner: Inner,
        \\    pub fn deinit(self: *Outer) void { _ = self; }
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    try testing.expectEqual(@as(usize, 2), model.types.len);
    try testing.expect(model.findType("Inner") != null);
    try testing.expect(model.findType("Outer") != null);
    try testing.expect(model.findType("Missing") == null);
    try testing.expect(model.typeHasMethod("Inner", "deinit"));
    try testing.expect(!model.typeHasMethod("Inner", "close"));
}

test "build: receiver detection" {
    const src: [:0]const u8 =
        \\const T = struct {
        \\    pub fn ptrSelf(self: *T) void { _ = self; }
        \\    pub fn constPtrSelf(self: *const T) void { _ = self; }
        \\    pub fn valueSelf(self: T) void { _ = self; }
        \\    pub fn aliasSelf(this: *T) void { _ = this; }
        \\    pub fn customRecv(t: *T) void { _ = t; }
        \\    pub fn noRecv() void {}
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    const ti = model.findType("T").?;
    const m_ptr = ti.findMethod("ptrSelf").?;
    try testing.expect(m_ptr.receiver != null);
    try testing.expect(m_ptr.receiver.?.is_ptr);
    try testing.expect(!m_ptr.receiver.?.is_const);

    const m_const = ti.findMethod("constPtrSelf").?;
    try testing.expect(m_const.receiver.?.is_ptr);
    try testing.expect(m_const.receiver.?.is_const);

    const m_val = ti.findMethod("valueSelf").?;
    try testing.expect(m_val.receiver != null);
    try testing.expect(!m_val.receiver.?.is_ptr);

    const m_this = ti.findMethod("aliasSelf").?;
    try testing.expect(m_this.receiver != null);
    try testing.expectEqualStrings("this", m_this.receiver.?.name);

    // `t: *T` — recognized because type matches enclosing name.
    const m_custom = ti.findMethod("customRecv").?;
    try testing.expect(m_custom.receiver != null);

    // `noRecv()` — no params, no receiver.
    const m_no = ti.findMethod("noRecv").?;
    try testing.expect(m_no.receiver == null);
}

test "build: top-level fn (not a method)" {
    const src: [:0]const u8 =
        \\const T = struct {
        \\    pub fn method(self: *T) void { _ = self; }
        \\};
        \\pub fn topLevelFn(x: u32) !void {
        \\    _ = x;
        \\}
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    try testing.expectEqual(@as(usize, 1), model.fns.len);
    const f = &model.fns[0];
    try testing.expectEqualStrings("topLevelFn", f.name);
    try testing.expect(f.is_pub);
    try testing.expect(f.returns_error_union);

    // The struct's `method` should NOT appear in model.fns —
    // it lives in T.methods.
    try testing.expect(model.findFn("method") == null);
}

test "build: union and enum" {
    const src: [:0]const u8 =
        \\const Tag = enum { a, b, c };
        \\const U = union(Tag) {
        \\    a: u32,
        \\    b: void,
        \\    c: f64,
        \\    pub fn kill(self: *U) void { _ = self; }
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    try testing.expectEqual(@as(usize, 2), model.types.len);
    const tag = model.findType("Tag").?;
    try testing.expectEqual(TypeKind.enum_, tag.kind);

    const u = model.findType("U").?;
    try testing.expectEqual(TypeKind.union_, u.kind);
    try testing.expect(u.hasMethod("kill"));
}

test "build: empty source" {
    var tree = try Ast.parse(testing.allocator, "", .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();
    try testing.expectEqual(@as(usize, 0), model.types.len);
    try testing.expectEqual(@as(usize, 0), model.fns.len);
}

test "build: nested type decls collected with parent link" {
    const src: [:0]const u8 =
        \\const Outer = struct {
        \\    x: u32,
        \\    pub fn deinit(self: *Outer) void { _ = self; }
        \\    const Inner = struct {
        \\        y: u32,
        \\        pub fn close(self: *Inner) void { _ = self; }
        \\    };
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    try testing.expectEqual(@as(usize, 2), model.types.len);
    const outer = model.findType("Outer").?;
    const inner = model.findType("Inner").?;
    try testing.expect(outer.parent == null);
    try testing.expect(inner.parent != null);
    // Inner's parent index points to Outer.
    try testing.expectEqual(outer, &model.types[inner.parent.?]);
    // Both pick up their methods so hasCleanupMethod works.
    try testing.expect(outer.hasMethod("deinit"));
    try testing.expect(inner.hasMethod("close"));
    try testing.expect(inner.hasCleanupMethod());
}

test "fieldIsPointer: detects *T / ?*T / *const T" {
    const src: [:0]const u8 =
        \\const Foo = struct {
        \\    val: Inner,
        \\    ptr: *Inner,
        \\    opt_ptr: ?*Inner,
        \\    const_ptr: *const Inner,
        \\    opt_val: ?Inner,
        \\    sl: []u8,
        \\};
        \\const Inner = struct {};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    try testing.expect(!model.fieldIsPointer("Foo", "val"));
    try testing.expect(model.fieldIsPointer("Foo", "ptr"));
    try testing.expect(model.fieldIsPointer("Foo", "opt_ptr"));
    try testing.expect(model.fieldIsPointer("Foo", "const_ptr"));
    try testing.expect(!model.fieldIsPointer("Foo", "opt_val"));
    try testing.expect(!model.fieldIsPointer("Foo", "sl"));
}

test "containingTypeOf: method's fn_decl resolves to its struct" {
    const src: [:0]const u8 =
        \\const Foo = struct {
        \\    x: u32,
        \\    pub fn deinit(self: *Foo) void { _ = self; }
        \\};
        \\pub fn top_level() void {}
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    // Find the deinit fn_decl + the top_level fn_decl.
    var idx: u32 = 1;
    var deinit_node: ?Ast.Node.Index = null;
    var top_node: ?Ast.Node.Index = null;
    while (idx < tree.nodes.len) : (idx += 1) {
        const n: Ast.Node.Index = @enumFromInt(idx);
        if (tree.nodeTag(n) != .fn_decl) continue;
        var buf: [1]Ast.Node.Index = undefined;
        const fp = @import("lexer.zig").fnProto(&tree, &buf, n).?;
        const name_tok = fp.name_token.?;
        if (std.mem.eql(u8, tree.tokenSlice(name_tok), "deinit")) deinit_node = n;
        if (std.mem.eql(u8, tree.tokenSlice(name_tok), "top_level")) top_node = n;
    }
    const dt = model.containingTypeOf(deinit_node.?);
    try testing.expect(dt != null);
    try testing.expectEqualStrings("Foo", dt.?.name);
    try testing.expect(model.containingTypeOf(top_node.?) == null);
}

test "fieldType: strips pointer/optional/const/slice wrappers" {
    const src: [:0]const u8 =
        \\const Bar = struct {
        \\    a: Inner,
        \\    b: *Inner,
        \\    c: ?*const Inner,
        \\    d: []const u8,
        \\    e: ?Inner,
        \\};
        \\const Inner = struct {};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    try testing.expectEqualStrings("Inner", model.fieldType("Bar", "a").?);
    try testing.expectEqualStrings("Inner", model.fieldType("Bar", "b").?);
    try testing.expectEqualStrings("Inner", model.fieldType("Bar", "c").?);
    try testing.expectEqualStrings("u8", model.fieldType("Bar", "d").?);
    try testing.expectEqualStrings("Inner", model.fieldType("Bar", "e").?);
}

test "isFlagOwnedField: detects X + X_allocated pair" {
    const src: [:0]const u8 =
        \\const Owner = struct {
        \\    data: []u8,
        \\    data_allocated: bool,
        \\    other: u32,
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    try testing.expect(model.isFlagOwnedField("Owner", "data"));
    try testing.expect(!model.isFlagOwnedField("Owner", "other"));
    try testing.expect(!model.isFlagOwnedField("Owner", "data_allocated"));
    try testing.expect(!model.isFlagOwnedField("Missing", "data"));
}

test "flagOwnedFields: returns the field-name set" {
    const src: [:0]const u8 =
        \\const Owner = struct {
        \\    one: []u8,
        \\    one_allocated: bool,
        \\    two: []u8,
        \\    two_allocated: bool,
        \\    three: u32,
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    const flagged = try model.flagOwnedFields(testing.allocator, "Owner");
    defer testing.allocator.free(flagged);
    try testing.expectEqual(@as(usize, 2), flagged.len);
    try testing.expectEqualStrings("one", flagged[0]);
    try testing.expectEqualStrings("two", flagged[1]);
}

test "build: doubly-nested type chains parent links" {
    const src: [:0]const u8 =
        \\const A = struct {
        \\    const B = struct {
        \\        const C = struct { x: u32 };
        \\    };
        \\};
    ;
    var tree = try Ast.parse(testing.allocator, src, .zig);
    defer tree.deinit(testing.allocator);
    var model = try build(testing.allocator, &tree);
    defer model.deinit();

    try testing.expectEqual(@as(usize, 3), model.types.len);
    const a = model.findType("A").?;
    const b = model.findType("B").?;
    const c = model.findType("C").?;
    try testing.expect(a.parent == null);
    try testing.expectEqual(a, &model.types[b.parent.?]);
    try testing.expectEqual(b, &model.types[c.parent.?]);
}
