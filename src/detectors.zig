//! Pattern-detector registry — class 2 of zbc's two check classes.
//!
//! A detector is a whole-file walk over `Ast` with no flow state: it
//! gets `(allocator, tree, FileCache, Config, problems)` and matches
//! token/AST shapes.  The other class — 10 invariants decided by the
//! per-fn CFG + abstract-interpretation worklist — is declared in
//! `flow/invariants.zig` and dispatched by `flow/cfg_transfer.zig`.
//!
//! Adding a detector: add `rules/<dir>/<id>.zig` exporting `check`, a
//! `rules/<dir>/<id>.md` doc, and a catalog entry in `rule_catalog.zig`,
//! then one field in `Rules` below.  The field name is the rule's
//! `config.Invariant` tag; the diagnostic id is derived from it.

const std = @import("std");

const Ast = std.zig.Ast;
const config_mod = @import("config.zig");
const problem_mod = @import("problem.zig");
const file_cache = @import("cache/file_cache.zig");

const Problem = problem_mod.Problem;
const Config = config_mod.Config;
const FileCache = file_cache.FileCache;

pub const Check = *const fn (
    std.mem.Allocator,
    *const Ast,
    *FileCache,
    *const Config,
    *std.ArrayListUnmanaged(Problem),
) anyerror!void;

pub const Detector = struct {
    id: []const u8,
    check: Check,
};

// ── Rule table ──────────────────────────────────────────────
//
// One line per rule.  The declaration name IS the rule id, written as a
// quoted identifier so kebab-case needs no conversion.  Zig has no
// comptime directory reflection, so this list stays written out; the
// dispatch table and the test refs derive from it, and `invariants.zig`
// proves each id is the kebab-case form of an `config.Invariant` tag.

const Rules = struct {
    pub const @"aliased-heap-dupe" = @import("rules/heap/aliased_heap_dupe.zig");
    pub const @"clobbered-by-struct-reset" = @import("rules/cleanup/clobbered_by_struct_reset.zig");
    pub const @"realloc-byte-count" = @import("rules/heap/realloc_byte_count.zig");
    pub const @"asymmetric-field-free" = @import("rules/cleanup/asymmetric_field_free.zig");
    pub const @"missing-errdefer-between-tries" = @import("rules/errdefer/missing_errdefer_between_tries.zig");
    pub const @"free-then-try-realloc" = @import("rules/heap/free_then_try_realloc.zig");
    pub const @"destroy-after-deinit-in-loop" = @import("rules/cleanup/destroy_after_deinit_in_loop.zig");
    pub const @"dead-errdefer-in-result-fn" = @import("rules/errdefer/dead_errdefer_in_result_fn.zig");
    pub const @"duplicate-errdefer" = @import("rules/errdefer/duplicate_errdefer.zig");
    pub const @"overwrite-without-deinit" = @import("rules/cleanup/overwrite_without_deinit.zig");
    pub const @"stack-fallback-escape" = @import("rules/borrow/stack_fallback_escape.zig");
    pub const @"unreleased-refs-on-error" = @import("rules/errdefer/unreleased_refs_on_error.zig");
    pub const @"hashmap-getptr-rehash" = @import("rules/collection/hashmap_getptr_rehash.zig");
    pub const @"arraylist-items-slice" = @import("rules/collection/arraylist_items_slice.zig");
    pub const @"arraylist-element-ptr" = @import("rules/collection/arraylist_element_ptr.zig");
    pub const @"fd-write-after-close" = @import("rules/misc/fd_write_after_close.zig");
    pub const @"slice-of-arena-into-heap" = @import("rules/heap/slice_of_arena_into_heap.zig");
    pub const @"free-without-null-then-check" = @import("rules/heap/free_without_null_then_check.zig");
    pub const @"tagged-union-retag-with-old-payload-read" = @import("rules/misc/tagged_union_retag_with_old_payload_read.zig");
    pub const @"union-deinit-without-inert-reset" = @import("rules/cleanup/union_deinit_without_inert_reset.zig");
    pub const @"self-undefined-after-destroy" = @import("rules/borrow/self_undefined_after_destroy.zig");
    pub const @"missing-errdefer-on-out-param" = @import("rules/errdefer/missing_errdefer_on_out_param.zig");
    pub const @"reset-skips-pooled-resource-release" = @import("rules/cleanup/reset_skips_pooled_resource_release.zig");
    pub const @"return-borrowed-payload" = @import("rules/borrow/return_borrowed_payload.zig");
    pub const @"unreleased-factory-handle" = @import("rules/cleanup/unreleased_factory_handle.zig");
    pub const @"memset-undef-after-len-truncation" = @import("rules/collection/memset_undef_after_len_truncation.zig");
    pub const @"publish-then-touch-self" = @import("rules/misc/publish_then_touch_self.zig");
    pub const @"missing-deinit-on-composed-owner" = @import("rules/cleanup/missing_deinit_on_composed_owner.zig");
    pub const @"owned-field-no-outer-cleanup" = @import("rules/cleanup/owned_field_no_outer_cleanup.zig");
    pub const @"borrowed-slice-into-out-param" = @import("rules/borrow/borrowed_slice_into_out_param.zig");
    pub const @"defer-and-errdefer-free-overlap" = @import("rules/errdefer/defer_and_errdefer_free_overlap.zig");
    pub const @"sentinel-strip-free-size-mismatch" = @import("rules/heap/sentinel_strip_free_size_mismatch.zig");
    pub const @"move-out-without-restore" = @import("rules/cleanup/move_out_without_restore.zig");
    pub const @"deinit-order-violates-construction-dep" = @import("rules/cleanup/deinit_order_violates_construction_dep.zig");
    pub const @"borrowed-slice-into-stack-buffer-returned" = @import("rules/borrow/borrowed_slice_into_stack_buffer_returned.zig");
    pub const @"getorput-unguarded-value-read" = @import("rules/collection/getorput_unguarded_value_read.zig");
    pub const @"hashmap-iter-mutation" = @import("rules/collection/hashmap_iter_mutation.zig");
    pub const @"iterator-invalidation-mutation" = @import("rules/collection/iterator_invalidation_mutation.zig");
    pub const @"thread-spawn-local-pointer" = @import("rules/misc/thread_spawn_local_pointer.zig");
    pub const @"self-pointer-in-returned-value" = @import("rules/borrow/self_pointer_in_returned_value.zig");
    pub const @"ref-before-ownership-transfer" = @import("rules/heap/ref_before_ownership_transfer.zig");
    pub const @"opt-capture-ptr-after-field-clear" = @import("rules/heap/opt_capture_ptr_after_field_clear.zig");
    pub const @"tagged-union-payload-early-exit" = @import("rules/misc/tagged_union_payload_early_exit.zig");
    pub const @"union-payload-ptr-after-variant-change" = @import("rules/misc/union_payload_ptr_after_variant_change.zig");
    pub const @"flag-reset-after-callback" = @import("rules/misc/flag_reset_after_callback.zig");
    pub const @"slice-loop-reentrant-grow" = @import("rules/collection/slice_loop_reentrant_grow.zig");
    pub const @"scope-push-pop-imbalance" = @import("rules/misc/scope_push_pop_imbalance.zig");
    pub const @"exit-callback-cross-thread" = @import("rules/misc/exit_callback_cross_thread.zig");
    pub const @"index-type-narrowing-wraparound" = @import("rules/misc/index_type_narrowing_wraparound.zig");
    pub const @"ref-counted-copy-without-dupe" = @import("rules/misc/ref_counted_copy_without_dupe.zig");
    pub const @"arraybuffer-slice-without-pin" = @import("rules/collection/arraybuffer_slice_without_pin.zig");
    pub const @"optional-fallback-wrong-side" = @import("rules/misc/optional_fallback_wrong_side.zig");
    pub const @"escape-skip-without-bounds-recheck" = @import("rules/misc/escape_skip_without_bounds_recheck.zig");
    pub const @"recursive-parse-without-stack-check" = @import("rules/misc/recursive_parse_without_stack_check.zig");
    pub const @"slice-from-fixed-offset-without-len-check" = @import("rules/misc/slice_from_fixed_offset_without_len_check.zig");
    pub const @"divmod-by-len-without-nonempty-guard" = @import("rules/misc/divmod_by_len_without_nonempty_guard.zig");
    pub const @"negate-then-shift-without-minint-check" = @import("rules/misc/negate_then_shift_without_minint_check.zig");
    pub const @"readint-unchecked-position-assignment" = @import("rules/misc/readint_unchecked_position_assignment.zig");
    pub const @"arraylist-sentinel-write-without-capacity" = @import("rules/collection/arraylist_sentinel_write_without_capacity.zig");
    pub const @"intfromfloat-without-clamp" = @import("rules/misc/intfromfloat_without_clamp.zig");
    pub const @"int-sum-overflow-in-bounds-cmp" = @import("rules/misc/int_sum_overflow_in_bounds_cmp.zig");
    pub const @"ptr-slice-without-bounds-check" = @import("rules/misc/ptr_slice_without_bounds_check.zig");
    pub const @"mutex-double-lock" = @import("rules/misc/mutex_double_lock.zig");
    pub const @"lock-held-across-early-exit" = @import("rules/misc/lock_held_across_early_exit.zig");
    pub const @"ptrfromint-zero" = @import("rules/misc/ptrfromint_zero.zig");
    pub const @"resize-result-discarded" = @import("rules/heap/resize_result_discarded.zig");
    pub const @"errdefer-alive-after-ownership-transfer" = @import("rules/errdefer/errdefer_alive_after_ownership_transfer.zig");
    pub const @"f32-narrowing-int-to-float" = @import("rules/misc/f32_narrowing_int_to_float.zig");
    pub const @"array-maxint-off-by-one" = @import("rules/misc/array_maxint_off_by_one.zig");
    pub const @"intcast-clamp-uses-max" = @import("rules/misc/intcast_clamp_uses_max.zig");
    pub const @"forced-unwrap-iterator-next" = @import("rules/misc/forced_unwrap_iterator_next.zig");
    pub const @"impossible-range-and" = @import("rules/misc/impossible_range_and.zig");
    pub const @"intcast-signed-timestamp" = @import("rules/misc/intcast_signed_timestamp.zig");
    pub const @"truncate-subtraction-without-guard" = @import("rules/misc/truncate_subtraction_without_guard.zig");
    pub const @"initcapacity-plain-add-overflow" = @import("rules/misc/initcapacity_plain_add_overflow.zig");
    pub const @"index-minus-one-without-zero-guard" = @import("rules/misc/index_minus_one_without_zero_guard.zig");
    pub const @"else-literal-absorbs-addend" = @import("rules/misc/else_literal_absorbs_addend.zig");
    pub const @"catch-error-panic" = @import("rules/misc/catch_error_panic.zig");
    pub const @"toutf8-inline-slice-borrow" = @import("rules/misc/toutf8_inline_slice_borrow.zig");
    pub const @"uv-return-value-intcast-truncation" = @import("rules/misc/uv_return_value_intcast_truncation.zig");
    pub const @"tryget-orelse-unreachable" = @import("rules/misc/tryget_orelse_unreachable.zig");
    pub const @"aligncast-on-byte-slice" = @import("rules/misc/aligncast_on_byte_slice.zig");
    pub const @"truncate-len-to-narrow-int" = @import("rules/misc/truncate_len_to_narrow_int.zig");
    pub const @"field-self-assign-with-cast" = @import("rules/misc/field_self_assign_with_cast.zig");
    pub const @"maybe-assert-panics" = @import("rules/misc/maybe_assert_panics.zig");
    pub const @"return-arraylist-items" = @import("rules/misc/return_arraylist_items.zig");
    pub const @"lessthan-uses-leq" = @import("rules/misc/lessthan_uses_leq.zig");
    pub const @"duplicate-defer-free" = @import("rules/misc/duplicate_defer_free.zig");
    pub const @"hashmap-getentry-forced-unwrap" = @import("rules/collection/hashmap_getentry_forced_unwrap.zig");
    pub const @"double-optional-ptr" = @import("rules/misc/double_optional_ptr.zig");
    pub const @"aligncast-on-optional-unwrap" = @import("rules/misc/aligncast_on_optional_unwrap.zig");
    pub const @"adjacent-decl-same-source-field" = @import("rules/misc/adjacent_decl_same_source_field.zig");
    pub const @"intcast-of-negated-signed" = @import("rules/misc/intcast_of_negated_signed.zig");
    pub const @"struct-literal-multiple-try" = @import("rules/misc/struct_literal_multiple_try.zig");
    pub const @"writeint-truncated-value" = @import("rules/misc/writeint_truncated_value.zig");
    pub const @"multiarray-items-deref-assign" = @import("rules/collection/multiarray_items_deref_assign.zig");
    pub const @"startswith-strip-off-by-one" = @import("rules/misc/startswith_strip_off_by_one.zig");
    pub const @"midpoint-addition-overflow" = @import("rules/misc/midpoint_addition_overflow.zig");
    pub const @"arena-allocator-free-noop" = @import("rules/misc/arena_allocator_free_noop.zig");
    pub const @"memcpy-overlapping-slices" = @import("rules/misc/memcpy_overlapping_slices.zig");
    pub const @"cmpxchgweak-orelse-break" = @import("rules/misc/cmpxchgweak_orelse_break.zig");
    pub const @"slice-write-at-len" = @import("rules/misc/slice_write_at_len.zig");
    pub const @"clamp-wrong-direction" = @import("rules/misc/clamp_wrong_direction.zig");
};

pub const detectors = blk: {
    const names = @typeInfo(Rules).@"struct".decl_names;
    var out: [names.len]Detector = undefined;
    for (names, 0..) |name, i| {
        out[i] = .{ .id = name, .check = @field(Rules, name).check };
    }
    break :blk out;
};

/// Dispatch all registered pattern detectors against `tree`.  `cache`
/// is amortized per-file shared state — rules borrow FileModel,
/// LocalBindings, FnSummary from it instead of building their own.
pub fn runEscape(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *FileCache,
    config: *const Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    for (detectors) |rule| {
        try rule.check(gpa, tree, cache, config, problems);
    }
}

// ── Tests ──────────────────────────────────────────────────

test "registry: every detector id is unique" {
    var seen: std.StringHashMap(void) = .init(std.testing.allocator);
    defer seen.deinit();
    for (detectors) |rule| {
        const gop = try seen.getOrPut(rule.id);
        try std.testing.expect(!gop.found_existing);
    }
}

test "registry: ids are kebab-case (lowercase + hyphen + digit)" {
    for (detectors) |rule| {
        for (rule.id) |c| {
            try std.testing.expect(c == '-' or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9'));
        }
    }
}

test "registry: pull in every rule module so inline tests run" {
    std.testing.refAllDecls(Rules);
}
