// oven-sh/bun#29879 — destructor loops `<h>.deinit()` over pointer-list
// items without per-item destroy.

const std = @import("std");

const ElementHandler = struct {
    pub fn deinit(_: *ElementHandler) void {}
};

const DocumentHandler = struct {
    pub fn deinit(_: *DocumentHandler) void {}
};

const LOLHTMLContext = struct {
    element_handlers: std.ArrayListUnmanaged(*ElementHandler) = .{},
    document_handlers: std.ArrayListUnmanaged(*DocumentHandler) = .{},

    // Bug — should fire on both loops.
    pub fn deinit(this: *LOLHTMLContext) void {
        for (this.element_handlers.items) |handler| {
            handler.deinit();
            // ← missing: std.heap.page_allocator.destroy(handler);
        }
        this.element_handlers.deinit(std.heap.page_allocator);

        for (this.document_handlers.items) |handler| {
            handler.deinit();
            // ← missing: std.heap.page_allocator.destroy(handler);
        }
        this.document_handlers.deinit(std.heap.page_allocator);
    }
};

// Control 1 — loop body includes destroy.  Should NOT fire.
const Fixed = struct {
    handlers: std.ArrayListUnmanaged(*ElementHandler) = .{},

    pub fn deinit(this: *Fixed) void {
        for (this.handlers.items) |handler| {
            handler.deinit();
            std.heap.page_allocator.destroy(handler);
        }
        this.handlers.deinit(std.heap.page_allocator);
    }
};

// Control 2 — list of value-typed items (no pointer).  Should NOT
// fire even without destroy.
const ValueList = struct {
    items_list: std.ArrayListUnmanaged(ElementHandler) = .{},

    pub fn deinit(this: *ValueList) void {
        for (this.items_list.items) |*item| {
            item.deinit();
        }
        this.items_list.deinit(std.heap.page_allocator);
    }
};

// Control 3 — outside a destructor, even with the missing-destroy
// shape.  Should NOT fire.
pub fn nonDestructor(ctx: *LOLHTMLContext) void {
    for (ctx.element_handlers.items) |handler| {
        handler.deinit();
    }
}
