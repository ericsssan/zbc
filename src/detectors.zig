//! Pattern-detector registry — class 2 of zbc's two check classes.
//!
//! A detector is a whole-file walk over `Ast` with no flow state: it
//! gets `(allocator, tree, FileCache, Config, problems)` and matches
//! token/AST shapes.  The other class — 10 invariants decided by the
//! per-fn CFG + abstract-interpretation worklist — is declared in
//! `flow/invariants.zig` and dispatched by `flow/cfg_transfer.zig`.
//!
//! Adding a detector: add `rules/<dir>/<id>.zig` exporting `check`,
//! a `rules/<dir>/<id>.md` doc, a catalog entry in `rule_catalog.zig`,
//! and one line here.  Its invariant tag must already exist in
//! `config.zig`; `invariants.zig` enforces the id ↔ tag mapping.

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

// ── Rule imports ─────────────────────────────────────────────

const aliased_heap_dupe_mod = @import("rules/heap/aliased_heap_dupe.zig");
const arraylist_element_ptr_mod = @import("rules/collection/arraylist_element_ptr.zig");
const arraylist_items_slice_mod = @import("rules/collection/arraylist_items_slice.zig");
const asymmetric_field_free_mod = @import("rules/cleanup/asymmetric_field_free.zig");
const borrowed_slice_into_out_param_mod = @import("rules/borrow/borrowed_slice_into_out_param.zig");
const borrowed_slice_into_stack_buffer_returned_mod = @import("rules/borrow/borrowed_slice_into_stack_buffer_returned.zig");
const clobbered_by_struct_reset_mod = @import("rules/cleanup/clobbered_by_struct_reset.zig");
const dead_errdefer_in_result_fn_mod = @import("rules/errdefer/dead_errdefer_in_result_fn.zig");
const defer_and_errdefer_free_overlap_mod = @import("rules/errdefer/defer_and_errdefer_free_overlap.zig");
const deinit_order_violates_construction_dep_mod = @import("rules/cleanup/deinit_order_violates_construction_dep.zig");
const destroy_after_deinit_in_loop_mod = @import("rules/cleanup/destroy_after_deinit_in_loop.zig");
const duplicate_errdefer_mod = @import("rules/errdefer/duplicate_errdefer.zig");
const fd_write_after_close_mod = @import("rules/misc/fd_write_after_close.zig");
const free_then_try_realloc_mod = @import("rules/heap/free_then_try_realloc.zig");
const free_without_null_then_check_mod = @import("rules/heap/free_without_null_then_check.zig");
const hashmap_getptr_rehash_mod = @import("rules/collection/hashmap_getptr_rehash.zig");
const getorput_unguarded_value_read_mod = @import("rules/collection/getorput_unguarded_value_read.zig");
const hashmap_iter_mutation_mod = @import("rules/collection/hashmap_iter_mutation.zig");
const iterator_invalidation_mutation_mod = @import("rules/collection/iterator_invalidation_mutation.zig");
const thread_spawn_local_pointer_mod = @import("rules/misc/thread_spawn_local_pointer.zig");
const self_pointer_in_returned_value_mod = @import("rules/borrow/self_pointer_in_returned_value.zig");
const memset_undef_after_len_truncation_mod = @import("rules/collection/memset_undef_after_len_truncation.zig");
const missing_deinit_on_composed_owner_mod = @import("rules/cleanup/missing_deinit_on_composed_owner.zig");
const missing_errdefer_between_tries_mod = @import("rules/errdefer/missing_errdefer_between_tries.zig");
const missing_errdefer_on_out_param_mod = @import("rules/errdefer/missing_errdefer_on_out_param.zig");
const move_out_without_restore_mod = @import("rules/cleanup/move_out_without_restore.zig");
const overwrite_without_deinit_mod = @import("rules/cleanup/overwrite_without_deinit.zig");
const owned_field_no_outer_cleanup_mod = @import("rules/cleanup/owned_field_no_outer_cleanup.zig");
const publish_then_touch_self_mod = @import("rules/misc/publish_then_touch_self.zig");
const realloc_byte_count_mod = @import("rules/heap/realloc_byte_count.zig");
const ref_before_ownership_transfer_mod = @import("rules/heap/ref_before_ownership_transfer.zig");
const opt_capture_ptr_after_field_clear_mod = @import("rules/heap/opt_capture_ptr_after_field_clear.zig");
const tagged_union_payload_early_exit_mod = @import("rules/misc/tagged_union_payload_early_exit.zig");
const union_payload_ptr_after_variant_change_mod = @import("rules/misc/union_payload_ptr_after_variant_change.zig");
const flag_reset_after_callback_mod = @import("rules/misc/flag_reset_after_callback.zig");
const slice_loop_reentrant_grow_mod = @import("rules/collection/slice_loop_reentrant_grow.zig");
const scope_push_pop_imbalance_mod = @import("rules/misc/scope_push_pop_imbalance.zig");
const exit_callback_cross_thread_mod = @import("rules/misc/exit_callback_cross_thread.zig");
const index_type_narrowing_wraparound_mod = @import("rules/misc/index_type_narrowing_wraparound.zig");
const ref_counted_copy_without_dupe_mod = @import("rules/misc/ref_counted_copy_without_dupe.zig");
const arraybuffer_slice_without_pin_mod = @import("rules/collection/arraybuffer_slice_without_pin.zig");
const optional_fallback_wrong_side_mod = @import("rules/misc/optional_fallback_wrong_side.zig");
const escape_skip_without_bounds_recheck_mod = @import("rules/misc/escape_skip_without_bounds_recheck.zig");
const recursive_parse_without_stack_check_mod = @import("rules/misc/recursive_parse_without_stack_check.zig");
const slice_from_fixed_offset_without_len_check_mod = @import("rules/misc/slice_from_fixed_offset_without_len_check.zig");
const divmod_by_len_without_nonempty_guard_mod = @import("rules/misc/divmod_by_len_without_nonempty_guard.zig");
const negate_then_shift_without_minint_check_mod = @import("rules/misc/negate_then_shift_without_minint_check.zig");
const readint_unchecked_position_assignment_mod = @import("rules/misc/readint_unchecked_position_assignment.zig");
const arraylist_sentinel_write_without_capacity_mod = @import("rules/collection/arraylist_sentinel_write_without_capacity.zig");
const intfromfloat_without_clamp_mod = @import("rules/misc/intfromfloat_without_clamp.zig");
const int_sum_overflow_in_bounds_cmp_mod = @import("rules/misc/int_sum_overflow_in_bounds_cmp.zig");
const ptr_slice_without_bounds_check_mod = @import("rules/misc/ptr_slice_without_bounds_check.zig");
const mutex_double_lock_mod = @import("rules/misc/mutex_double_lock.zig");
const lock_held_across_early_exit_mod = @import("rules/misc/lock_held_across_early_exit.zig");
const ptrfromint_zero_mod = @import("rules/misc/ptrfromint_zero.zig");
const resize_result_discarded_mod = @import("rules/heap/resize_result_discarded.zig");
const errdefer_alive_after_ownership_transfer_mod = @import("rules/errdefer/errdefer_alive_after_ownership_transfer.zig");
const f32_narrowing_int_to_float_mod = @import("rules/misc/f32_narrowing_int_to_float.zig");
const array_maxint_off_by_one_mod = @import("rules/misc/array_maxint_off_by_one.zig");
const intcast_clamp_uses_max_mod = @import("rules/misc/intcast_clamp_uses_max.zig");
const forced_unwrap_iterator_next_mod = @import("rules/misc/forced_unwrap_iterator_next.zig");
const impossible_range_and_mod = @import("rules/misc/impossible_range_and.zig");
const intcast_signed_timestamp_mod = @import("rules/misc/intcast_signed_timestamp.zig");
const truncate_subtraction_without_guard_mod = @import("rules/misc/truncate_subtraction_without_guard.zig");
const initcapacity_plain_add_overflow_mod = @import("rules/misc/initcapacity_plain_add_overflow.zig");
const index_minus_one_without_zero_guard_mod = @import("rules/misc/index_minus_one_without_zero_guard.zig");
const else_literal_absorbs_addend_mod = @import("rules/misc/else_literal_absorbs_addend.zig");
const catch_error_panic_mod = @import("rules/misc/catch_error_panic.zig");
const toutf8_inline_slice_borrow_mod = @import("rules/misc/toutf8_inline_slice_borrow.zig");
const uv_return_value_intcast_truncation_mod = @import("rules/misc/uv_return_value_intcast_truncation.zig");
const tryget_orelse_unreachable_mod = @import("rules/misc/tryget_orelse_unreachable.zig");
const aligncast_on_byte_slice_mod = @import("rules/misc/aligncast_on_byte_slice.zig");
const truncate_len_to_narrow_int_mod = @import("rules/misc/truncate_len_to_narrow_int.zig");
const field_self_assign_with_cast_mod = @import("rules/misc/field_self_assign_with_cast.zig");
const maybe_assert_panics_mod = @import("rules/misc/maybe_assert_panics.zig");
const return_arraylist_items_mod = @import("rules/misc/return_arraylist_items.zig");
const lessthan_uses_leq_mod = @import("rules/misc/lessthan_uses_leq.zig");
const duplicate_defer_free_mod = @import("rules/misc/duplicate_defer_free.zig");
const hashmap_getentry_forced_unwrap_mod = @import("rules/collection/hashmap_getentry_forced_unwrap.zig");
const multiarray_items_deref_assign_mod = @import("rules/collection/multiarray_items_deref_assign.zig");
const startswith_strip_off_by_one_mod = @import("rules/misc/startswith_strip_off_by_one.zig");
const midpoint_addition_overflow_mod = @import("rules/misc/midpoint_addition_overflow.zig");
const arena_allocator_free_noop_mod = @import("rules/misc/arena_allocator_free_noop.zig");
const memcpy_overlapping_slices_mod = @import("rules/misc/memcpy_overlapping_slices.zig");
const cmpxchgweak_orelse_break_mod = @import("rules/misc/cmpxchgweak_orelse_break.zig");
const slice_write_at_len_mod = @import("rules/misc/slice_write_at_len.zig");
const clamp_wrong_direction_mod = @import("rules/misc/clamp_wrong_direction.zig");
const double_optional_ptr_mod = @import("rules/misc/double_optional_ptr.zig");
const aligncast_on_optional_unwrap_mod = @import("rules/misc/aligncast_on_optional_unwrap.zig");
const adjacent_decl_same_source_field_mod = @import("rules/misc/adjacent_decl_same_source_field.zig");
const intcast_of_negated_signed_mod = @import("rules/misc/intcast_of_negated_signed.zig");
const struct_literal_multiple_try_mod = @import("rules/misc/struct_literal_multiple_try.zig");
const writeint_truncated_value_mod = @import("rules/misc/writeint_truncated_value.zig");
const reset_skips_pooled_resource_release_mod = @import("rules/cleanup/reset_skips_pooled_resource_release.zig");
const return_borrowed_payload_mod = @import("rules/borrow/return_borrowed_payload.zig");
const self_undefined_after_destroy_mod = @import("rules/borrow/self_undefined_after_destroy.zig");
const sentinel_strip_free_size_mismatch_mod = @import("rules/heap/sentinel_strip_free_size_mismatch.zig");
const slice_of_arena_into_heap_mod = @import("rules/heap/slice_of_arena_into_heap.zig");
const stack_fallback_escape_mod = @import("rules/borrow/stack_fallback_escape.zig");
const tagged_union_retag_with_old_payload_read_mod = @import("rules/misc/tagged_union_retag_with_old_payload_read.zig");
const union_deinit_without_inert_reset_mod = @import("rules/cleanup/union_deinit_without_inert_reset.zig");
const unreleased_factory_handle_mod = @import("rules/cleanup/unreleased_factory_handle.zig");
const unreleased_refs_on_error_mod = @import("rules/errdefer/unreleased_refs_on_error.zig");

pub const detectors = [_]Detector{
    .{ .id = "aliased-heap-dupe",                          .check = aliased_heap_dupe_mod.check },
    .{ .id = "clobbered-by-struct-reset",                  .check = clobbered_by_struct_reset_mod.check },
    .{ .id = "realloc-byte-count",                         .check = realloc_byte_count_mod.check },
    .{ .id = "asymmetric-field-free",                      .check = asymmetric_field_free_mod.check },
    .{ .id = "missing-errdefer-between-tries",             .check = missing_errdefer_between_tries_mod.check },
    .{ .id = "free-then-try-realloc",                      .check = free_then_try_realloc_mod.check },
    .{ .id = "destroy-after-deinit-in-loop",               .check = destroy_after_deinit_in_loop_mod.check },
    .{ .id = "dead-errdefer-in-result-fn",                 .check = dead_errdefer_in_result_fn_mod.check },
    .{ .id = "duplicate-errdefer",                         .check = duplicate_errdefer_mod.check },
    .{ .id = "overwrite-without-deinit",                   .check = overwrite_without_deinit_mod.check },
    .{ .id = "stack-fallback-escape",                      .check = stack_fallback_escape_mod.check },
    .{ .id = "unreleased-refs-on-error",                   .check = unreleased_refs_on_error_mod.check },
    .{ .id = "hashmap-getptr-rehash",                      .check = hashmap_getptr_rehash_mod.check },
    .{ .id = "arraylist-items-slice",                      .check = arraylist_items_slice_mod.check },
    .{ .id = "arraylist-element-ptr",                      .check = arraylist_element_ptr_mod.check },
    .{ .id = "fd-write-after-close",                       .check = fd_write_after_close_mod.check },
    .{ .id = "slice-of-arena-into-heap",                   .check = slice_of_arena_into_heap_mod.check },
    .{ .id = "free-without-null-then-check",               .check = free_without_null_then_check_mod.check },
    .{ .id = "tagged-union-retag-with-old-payload-read",   .check = tagged_union_retag_with_old_payload_read_mod.check },
    .{ .id = "union-deinit-without-inert-reset",           .check = union_deinit_without_inert_reset_mod.check },
    .{ .id = "self-undefined-after-destroy",               .check = self_undefined_after_destroy_mod.check },
    .{ .id = "missing-errdefer-on-out-param",              .check = missing_errdefer_on_out_param_mod.check },
    .{ .id = "reset-skips-pooled-resource-release",        .check = reset_skips_pooled_resource_release_mod.check },
    .{ .id = "return-borrowed-payload",                    .check = return_borrowed_payload_mod.check },
    .{ .id = "unreleased-factory-handle",                  .check = unreleased_factory_handle_mod.check },
    .{ .id = "memset-undef-after-len-truncation",          .check = memset_undef_after_len_truncation_mod.check },
    .{ .id = "publish-then-touch-self",                    .check = publish_then_touch_self_mod.check },
    .{ .id = "missing-deinit-on-composed-owner",           .check = missing_deinit_on_composed_owner_mod.check },
    .{ .id = "owned-field-no-outer-cleanup",               .check = owned_field_no_outer_cleanup_mod.check },
    .{ .id = "borrowed-slice-into-out-param",              .check = borrowed_slice_into_out_param_mod.check },
    .{ .id = "defer-and-errdefer-free-overlap",            .check = defer_and_errdefer_free_overlap_mod.check },
    .{ .id = "sentinel-strip-free-size-mismatch",          .check = sentinel_strip_free_size_mismatch_mod.check },
    .{ .id = "move-out-without-restore",                   .check = move_out_without_restore_mod.check },
    .{ .id = "deinit-order-violates-construction-dep",     .check = deinit_order_violates_construction_dep_mod.check },
    .{ .id = "borrowed-slice-into-stack-buffer-returned",  .check = borrowed_slice_into_stack_buffer_returned_mod.check },
    .{ .id = "getorput-unguarded-value-read",              .check = getorput_unguarded_value_read_mod.check },
    .{ .id = "hashmap-iter-mutation",                      .check = hashmap_iter_mutation_mod.check },
    .{ .id = "iterator-invalidation-mutation",             .check = iterator_invalidation_mutation_mod.check },
    .{ .id = "thread-spawn-local-pointer",                 .check = thread_spawn_local_pointer_mod.check },
    .{ .id = "self-pointer-in-returned-value",             .check = self_pointer_in_returned_value_mod.check },
    .{ .id = "ref-before-ownership-transfer",              .check = ref_before_ownership_transfer_mod.check },
    .{ .id = "opt-capture-ptr-after-field-clear",          .check = opt_capture_ptr_after_field_clear_mod.check },
    .{ .id = "tagged-union-payload-early-exit",            .check = tagged_union_payload_early_exit_mod.check },
    .{ .id = "union-payload-ptr-after-variant-change",     .check = union_payload_ptr_after_variant_change_mod.check },
    .{ .id = "flag-reset-after-callback",                  .check = flag_reset_after_callback_mod.check },
    .{ .id = "slice-loop-reentrant-grow",                  .check = slice_loop_reentrant_grow_mod.check },
    .{ .id = "scope-push-pop-imbalance",                   .check = scope_push_pop_imbalance_mod.check },
    .{ .id = "exit-callback-cross-thread",                 .check = exit_callback_cross_thread_mod.check },
    .{ .id = "index-type-narrowing-wraparound",            .check = index_type_narrowing_wraparound_mod.check },
    .{ .id = "ref-counted-copy-without-dupe",              .check = ref_counted_copy_without_dupe_mod.check },
    .{ .id = "arraybuffer-slice-without-pin",               .check = arraybuffer_slice_without_pin_mod.check },
    .{ .id = "optional-fallback-wrong-side",                .check = optional_fallback_wrong_side_mod.check },
    .{ .id = "escape-skip-without-bounds-recheck",          .check = escape_skip_without_bounds_recheck_mod.check },
    .{ .id = "recursive-parse-without-stack-check",      .check = recursive_parse_without_stack_check_mod.check },
    .{ .id = "slice-from-fixed-offset-without-len-check",   .check = slice_from_fixed_offset_without_len_check_mod.check },
    .{ .id = "divmod-by-len-without-nonempty-guard",        .check = divmod_by_len_without_nonempty_guard_mod.check },
    .{ .id = "negate-then-shift-without-minint-check",      .check = negate_then_shift_without_minint_check_mod.check },
    .{ .id = "readint-unchecked-position-assignment",       .check = readint_unchecked_position_assignment_mod.check },
    .{ .id = "arraylist-sentinel-write-without-capacity",  .check = arraylist_sentinel_write_without_capacity_mod.check },
    .{ .id = "intfromfloat-without-clamp",                 .check = intfromfloat_without_clamp_mod.check },
    .{ .id = "int-sum-overflow-in-bounds-cmp",             .check = int_sum_overflow_in_bounds_cmp_mod.check },
    .{ .id = "ptr-slice-without-bounds-check",             .check = ptr_slice_without_bounds_check_mod.check },
    .{ .id = "mutex-double-lock",                          .check = mutex_double_lock_mod.check },
    .{ .id = "lock-held-across-early-exit",                .check = lock_held_across_early_exit_mod.check },
    .{ .id = "ptrfromint-zero",                            .check = ptrfromint_zero_mod.check },
    .{ .id = "resize-result-discarded",                    .check = resize_result_discarded_mod.check },
    .{ .id = "errdefer-alive-after-ownership-transfer",    .check = errdefer_alive_after_ownership_transfer_mod.check },
    .{ .id = "f32-narrowing-int-to-float",                .check = f32_narrowing_int_to_float_mod.check },
    .{ .id = "array-maxint-off-by-one",                  .check = array_maxint_off_by_one_mod.check },
    .{ .id = "intcast-clamp-uses-max",                   .check = intcast_clamp_uses_max_mod.check },
    .{ .id = "forced-unwrap-iterator-next",              .check = forced_unwrap_iterator_next_mod.check },
    .{ .id = "impossible-range-and",                    .check = impossible_range_and_mod.check },
    .{ .id = "intcast-signed-timestamp",                .check = intcast_signed_timestamp_mod.check },
    .{ .id = "truncate-subtraction-without-guard",      .check = truncate_subtraction_without_guard_mod.check },
    .{ .id = "initcapacity-plain-add-overflow",         .check = initcapacity_plain_add_overflow_mod.check },
    .{ .id = "index-minus-one-without-zero-guard",      .check = index_minus_one_without_zero_guard_mod.check },
    .{ .id = "else-literal-absorbs-addend",             .check = else_literal_absorbs_addend_mod.check },
    .{ .id = "catch-error-panic",                       .check = catch_error_panic_mod.check },
    .{ .id = "toutf8-inline-slice-borrow",              .check = toutf8_inline_slice_borrow_mod.check },
    .{ .id = "uv-return-value-intcast-truncation",      .check = uv_return_value_intcast_truncation_mod.check },
    .{ .id = "tryget-orelse-unreachable",               .check = tryget_orelse_unreachable_mod.check },
    .{ .id = "aligncast-on-byte-slice",                 .check = aligncast_on_byte_slice_mod.check },
    .{ .id = "truncate-len-to-narrow-int",              .check = truncate_len_to_narrow_int_mod.check },
    .{ .id = "field-self-assign-with-cast",             .check = field_self_assign_with_cast_mod.check },
    .{ .id = "maybe-assert-panics",                     .check = maybe_assert_panics_mod.check },
    .{ .id = "return-arraylist-items",                  .check = return_arraylist_items_mod.check },
    .{ .id = "lessthan-uses-leq",                       .check = lessthan_uses_leq_mod.check },
    .{ .id = "duplicate-defer-free",                    .check = duplicate_defer_free_mod.check },
    .{ .id = "hashmap-getentry-forced-unwrap",          .check = hashmap_getentry_forced_unwrap_mod.check },
    .{ .id = "double-optional-ptr",                    .check = double_optional_ptr_mod.check },
    .{ .id = "aligncast-on-optional-unwrap",           .check = aligncast_on_optional_unwrap_mod.check },
    .{ .id = "adjacent-decl-same-source-field",        .check = adjacent_decl_same_source_field_mod.check },
    .{ .id = "intcast-of-negated-signed",               .check = intcast_of_negated_signed_mod.check },
    .{ .id = "struct-literal-multiple-try",             .check = struct_literal_multiple_try_mod.check },
    .{ .id = "writeint-truncated-value",                .check = writeint_truncated_value_mod.check },
    .{ .id = "multiarray-items-deref-assign",           .check = multiarray_items_deref_assign_mod.check },
    .{ .id = "startswith-strip-off-by-one",             .check = startswith_strip_off_by_one_mod.check },
    .{ .id = "midpoint-addition-overflow",              .check = midpoint_addition_overflow_mod.check },
    .{ .id = "arena-allocator-free-noop",               .check = arena_allocator_free_noop_mod.check },
    .{ .id = "memcpy-overlapping-slices",               .check = memcpy_overlapping_slices_mod.check },
    .{ .id = "cmpxchgweak-orelse-break",                .check = cmpxchgweak_orelse_break_mod.check },
    .{ .id = "slice-write-at-len",                     .check = slice_write_at_len_mod.check },
    .{ .id = "clamp-wrong-direction",                  .check = clamp_wrong_direction_mod.check },
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
    _ = aliased_heap_dupe_mod;
    _ = arraylist_element_ptr_mod;
    _ = arraylist_items_slice_mod;
    _ = asymmetric_field_free_mod;
    _ = borrowed_slice_into_out_param_mod;
    _ = borrowed_slice_into_stack_buffer_returned_mod;
    _ = clobbered_by_struct_reset_mod;
    _ = dead_errdefer_in_result_fn_mod;
    _ = defer_and_errdefer_free_overlap_mod;
    _ = deinit_order_violates_construction_dep_mod;
    _ = destroy_after_deinit_in_loop_mod;
    _ = duplicate_errdefer_mod;
    _ = getorput_unguarded_value_read_mod;
    _ = hashmap_iter_mutation_mod;
    _ = iterator_invalidation_mutation_mod;
    _ = thread_spawn_local_pointer_mod;
    _ = self_pointer_in_returned_value_mod;
    _ = fd_write_after_close_mod;
    _ = free_then_try_realloc_mod;
    _ = free_without_null_then_check_mod;
    _ = hashmap_getptr_rehash_mod;
    _ = memset_undef_after_len_truncation_mod;
    _ = missing_deinit_on_composed_owner_mod;
    _ = missing_errdefer_between_tries_mod;
    _ = missing_errdefer_on_out_param_mod;
    _ = move_out_without_restore_mod;
    _ = overwrite_without_deinit_mod;
    _ = owned_field_no_outer_cleanup_mod;
    _ = publish_then_touch_self_mod;
    _ = realloc_byte_count_mod;
    _ = reset_skips_pooled_resource_release_mod;
    _ = return_borrowed_payload_mod;
    _ = self_undefined_after_destroy_mod;
    _ = sentinel_strip_free_size_mismatch_mod;
    _ = slice_of_arena_into_heap_mod;
    _ = stack_fallback_escape_mod;
    _ = tagged_union_retag_with_old_payload_read_mod;
    _ = union_deinit_without_inert_reset_mod;
    _ = unreleased_factory_handle_mod;
    _ = unreleased_refs_on_error_mod;
    _ = ref_before_ownership_transfer_mod;
    _ = opt_capture_ptr_after_field_clear_mod;
    _ = tagged_union_payload_early_exit_mod;
    _ = union_payload_ptr_after_variant_change_mod;
    _ = flag_reset_after_callback_mod;
    _ = slice_loop_reentrant_grow_mod;
    _ = scope_push_pop_imbalance_mod;
    _ = exit_callback_cross_thread_mod;
    _ = index_type_narrowing_wraparound_mod;
    _ = ref_counted_copy_without_dupe_mod;
    _ = arraybuffer_slice_without_pin_mod;
    _ = optional_fallback_wrong_side_mod;
    _ = escape_skip_without_bounds_recheck_mod;
    _ = recursive_parse_without_stack_check_mod;
    _ = slice_from_fixed_offset_without_len_check_mod;
    _ = divmod_by_len_without_nonempty_guard_mod;
    _ = negate_then_shift_without_minint_check_mod;
    _ = readint_unchecked_position_assignment_mod;
    _ = arraylist_sentinel_write_without_capacity_mod;
    _ = intfromfloat_without_clamp_mod;
    _ = int_sum_overflow_in_bounds_cmp_mod;
    _ = ptr_slice_without_bounds_check_mod;
    _ = mutex_double_lock_mod;
    _ = lock_held_across_early_exit_mod;
    _ = ptrfromint_zero_mod;
    _ = resize_result_discarded_mod;
    _ = errdefer_alive_after_ownership_transfer_mod;
    _ = f32_narrowing_int_to_float_mod;
    _ = array_maxint_off_by_one_mod;
    _ = intcast_clamp_uses_max_mod;
    _ = forced_unwrap_iterator_next_mod;
    _ = impossible_range_and_mod;
    _ = intcast_signed_timestamp_mod;
    _ = truncate_subtraction_without_guard_mod;
    _ = initcapacity_plain_add_overflow_mod;
    _ = index_minus_one_without_zero_guard_mod;
    _ = else_literal_absorbs_addend_mod;
    _ = catch_error_panic_mod;
    _ = toutf8_inline_slice_borrow_mod;
    _ = uv_return_value_intcast_truncation_mod;
    _ = tryget_orelse_unreachable_mod;
    _ = aligncast_on_byte_slice_mod;
    _ = truncate_len_to_narrow_int_mod;
    _ = field_self_assign_with_cast_mod;
    _ = maybe_assert_panics_mod;
    _ = return_arraylist_items_mod;
    _ = lessthan_uses_leq_mod;
    _ = duplicate_defer_free_mod;
    _ = hashmap_getentry_forced_unwrap_mod;
    _ = double_optional_ptr_mod;
    _ = aligncast_on_optional_unwrap_mod;
    _ = adjacent_decl_same_source_field_mod;
    _ = intcast_of_negated_signed_mod;
    _ = struct_literal_multiple_try_mod;
    _ = writeint_truncated_value_mod;
    _ = multiarray_items_deref_assign_mod;
    _ = startswith_strip_off_by_one_mod;
    _ = midpoint_addition_overflow_mod;
    _ = arena_allocator_free_noop_mod;
    _ = memcpy_overlapping_slices_mod;
    _ = cmpxchgweak_orelse_break_mod;
    _ = slice_write_at_len_mod;
    _ = clamp_wrong_direction_mod;
}
