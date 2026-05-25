//! Comptime rule registry — the canonical list of escape-analysis
//! pattern rules.
//!
//! Adding a rule: import its module here, append one entry to
//! `escape_rules`, and add the invariant to `config.zig`.  lib.zig
//! iterates this list — no manual dispatch site to edit.

const std = @import("std");
const Ast = std.zig.Ast;

const config_mod = @import("config.zig");
const problem_mod = @import("problem.zig");
const file_cache = @import("file_cache.zig");

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

pub const Rule = struct {
    id: []const u8,
    check: Check,
};

// ── Rule imports ─────────────────────────────────────────────

const aliased_heap_dupe_mod = @import("rules/aliased_heap_dupe.zig");
const arraylist_items_slice_mod = @import("rules/arraylist_items_slice.zig");
const assert_on_untrusted_input_mod = @import("rules/assert_on_untrusted_input.zig");
const asymmetric_field_free_mod = @import("rules/asymmetric_field_free.zig");
const borrowed_slice_into_out_param_mod = @import("rules/borrowed_slice_into_out_param.zig");
const borrowed_slice_into_stack_buffer_returned_mod = @import("rules/borrowed_slice_into_stack_buffer_returned.zig");
const clobbered_by_struct_reset_mod = @import("rules/clobbered_by_struct_reset.zig");
const dead_errdefer_in_result_fn_mod = @import("rules/dead_errdefer_in_result_fn.zig");
const defer_and_errdefer_free_overlap_mod = @import("rules/defer_and_errdefer_free_overlap.zig");
const deinit_order_violates_construction_dep_mod = @import("rules/deinit_order_violates_construction_dep.zig");
const destroy_after_deinit_in_loop_mod = @import("rules/destroy_after_deinit_in_loop.zig");
const duplicate_errdefer_mod = @import("rules/duplicate_errdefer.zig");
const fd_write_after_close_mod = @import("rules/fd_write_after_close.zig");
const free_then_try_realloc_mod = @import("rules/free_then_try_realloc.zig");
const free_without_null_then_check_mod = @import("rules/free_without_null_then_check.zig");
const hashmap_getptr_rehash_mod = @import("rules/hashmap_getptr_rehash.zig");
const iterator_invalidation_mutation_mod = @import("rules/iterator_invalidation_mutation.zig");
const thread_spawn_local_pointer_mod = @import("rules/thread_spawn_local_pointer.zig");
const memset_undef_after_len_truncation_mod = @import("rules/memset_undef_after_len_truncation.zig");
const missing_deinit_on_composed_owner_mod = @import("rules/missing_deinit_on_composed_owner.zig");
const missing_errdefer_between_tries_mod = @import("rules/missing_errdefer_between_tries.zig");
const missing_errdefer_on_out_param_mod = @import("rules/missing_errdefer_on_out_param.zig");
const move_out_without_restore_mod = @import("rules/move_out_without_restore.zig");
const overwrite_without_deinit_mod = @import("rules/overwrite_without_deinit.zig");
const owned_field_no_outer_cleanup_mod = @import("rules/owned_field_no_outer_cleanup.zig");
const publish_then_touch_self_mod = @import("rules/publish_then_touch_self.zig");
const realloc_byte_count_mod = @import("rules/realloc_byte_count.zig");
const reset_skips_pooled_resource_release_mod = @import("rules/reset_skips_pooled_resource_release.zig");
const return_borrowed_payload_mod = @import("rules/return_borrowed_payload.zig");
const self_undefined_after_destroy_mod = @import("rules/self_undefined_after_destroy.zig");
const sentinel_strip_free_size_mismatch_mod = @import("rules/sentinel_strip_free_size_mismatch.zig");
const slice_of_arena_into_heap_mod = @import("rules/slice_of_arena_into_heap.zig");
const stack_fallback_escape_mod = @import("rules/stack_fallback_escape.zig");
const tagged_union_retag_with_old_payload_read_mod = @import("rules/tagged_union_retag_with_old_payload_read.zig");
const union_deinit_without_inert_reset_mod = @import("rules/union_deinit_without_inert_reset.zig");
const unreleased_factory_handle_mod = @import("rules/unreleased_factory_handle.zig");
const unreleased_refs_on_error_mod = @import("rules/unreleased_refs_on_error.zig");

// ── The registry ─────────────────────────────────────────────
//
// Order matches the original dispatch sequence in lib.zig.
// Rules that need Db run after CFG analysis populates it.

pub const escape_rules = [_]Rule{
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
    .{ .id = "assert-on-untrusted-input",                  .check = assert_on_untrusted_input_mod.check },
    .{ .id = "missing-deinit-on-composed-owner",           .check = missing_deinit_on_composed_owner_mod.check },
    .{ .id = "owned-field-no-outer-cleanup",               .check = owned_field_no_outer_cleanup_mod.check },
    .{ .id = "borrowed-slice-into-out-param",              .check = borrowed_slice_into_out_param_mod.check },
    .{ .id = "defer-and-errdefer-free-overlap",            .check = defer_and_errdefer_free_overlap_mod.check },
    .{ .id = "sentinel-strip-free-size-mismatch",          .check = sentinel_strip_free_size_mismatch_mod.check },
    .{ .id = "move-out-without-restore",                   .check = move_out_without_restore_mod.check },
    .{ .id = "deinit-order-violates-construction-dep",     .check = deinit_order_violates_construction_dep_mod.check },
    .{ .id = "borrowed-slice-into-stack-buffer-returned",  .check = borrowed_slice_into_stack_buffer_returned_mod.check },
    .{ .id = "iterator-invalidation-mutation",             .check = iterator_invalidation_mutation_mod.check },
    .{ .id = "thread-spawn-local-pointer",                 .check = thread_spawn_local_pointer_mod.check },
};

/// Dispatch all registered escape rules against `tree`.  `cache` is
/// amortized per-file shared state — rules borrow FileModel +
/// LocalBindings + FnSummary from it instead of building their own.
pub fn runEscape(
    gpa: std.mem.Allocator,
    tree: *const Ast,
    cache: *FileCache,
    config: *const Config,
    problems: *std.ArrayListUnmanaged(Problem),
) !void {
    for (escape_rules) |rule| {
        try rule.check(gpa, tree, cache, config, problems);
    }
}

// ── Tests ──────────────────────────────────────────────────

test "registry: every id appears exactly once" {
    var seen: std.StringHashMap(void) = .init(std.testing.allocator);
    defer seen.deinit();
    for (escape_rules) |rule| {
        const gop = try seen.getOrPut(rule.id);
        try std.testing.expect(!gop.found_existing);
    }
}

test "registry: ids are kebab-case (lowercase + hyphen)" {
    for (escape_rules) |rule| {
        for (rule.id) |c| {
            try std.testing.expect(c == '-' or (c >= 'a' and c <= 'z'));
        }
    }
}

test "registry: pull in every rule module so inline tests run" {
    _ = aliased_heap_dupe_mod;
    _ = arraylist_items_slice_mod;
    _ = assert_on_untrusted_input_mod;
    _ = asymmetric_field_free_mod;
    _ = borrowed_slice_into_out_param_mod;
    _ = borrowed_slice_into_stack_buffer_returned_mod;
    _ = clobbered_by_struct_reset_mod;
    _ = dead_errdefer_in_result_fn_mod;
    _ = defer_and_errdefer_free_overlap_mod;
    _ = deinit_order_violates_construction_dep_mod;
    _ = destroy_after_deinit_in_loop_mod;
    _ = duplicate_errdefer_mod;
    _ = iterator_invalidation_mutation_mod;
    _ = thread_spawn_local_pointer_mod;
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
}
