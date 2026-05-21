// Isolated repro of the oven-sh/bun#29968 bug pattern in standalone form.

const std = @import("std");

const ColumnDefinition41 = struct {
    pub fn deinit(_: *@This()) void {}
};

const Header = struct { field_count: usize };

const Statement = struct {
    columns: []ColumnDefinition41 = &.{},
    cached_structure: struct {
        pub fn deinit(_: *@This()) void {}
    } = .{},
    columns_received: usize = 0,
    execution_flags: struct {
        needs_duplicate_check: bool = false,
    } = .{},
};

pub fn handleResultSet(statement: *Statement, header: Header) !void {
    if (statement.columns.len != header.field_count) {
        statement.cached_structure.deinit();
        statement.cached_structure = .{};
        if (statement.columns.len > 0) {
            for (statement.columns) |*column| {
                column.deinit();
            }
            std.heap.page_allocator.free(statement.columns);
        }
        statement.columns = try std.heap.page_allocator.alloc(ColumnDefinition41, header.field_count);
        for (statement.columns) |*col| col.* = .{};
        statement.columns_received = 0;
    }
    statement.execution_flags.needs_duplicate_check = true;
}
