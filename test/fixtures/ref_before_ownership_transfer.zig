// oven-sh/bun#30137 — `query.ref()` called before `MySQLQuery.init(query, …)`.
// The init takes ownership of query and decrements the refcount once on
// cleanup; the extra `.ref()` by the caller is never balanced → leak.

const Allocator = struct {};

const MySQLQuery = struct {
    query: *Query,
    pub fn init(q: *Query, _: Allocator, _: u32) MySQLQuery {
        return .{ .query = q };
    }
    pub fn deinit(self: *MySQLQuery) void {
        self.query.deref();
    }
};

const Query = struct {
    ref_count: u32 = 1,

    pub fn ref(self: *Query) void {
        self.ref_count += 1;
    }

    pub fn deref(self: *Query) void {
        self.ref_count -= 1;
        // BUG: if ref_count was not 0, it should now be, but the extra .ref()
        // means ref_count is 1 here instead of 0 → never freed.
    }
};

const allocator: Allocator = .{};

// Bug — should fire on `query.ref()`.
pub fn setupBuggy(query: *Query) void {
    query.ref(); // ← extra ref; MySQLQuery.init will deref once on deinit
    var mysql_query = MySQLQuery.init(query, allocator, 0);
    _ = &mysql_query;
}

// Control 1 — no .ref() before init.  Should NOT fire.
pub fn setupFixed(query: *Query) void {
    var mysql_query = MySQLQuery.init(query, allocator, 0);
    _ = &mysql_query;
}

// Control 2 — .ref() with paired defer .deref().  Should NOT fire.
pub fn setupWithExplicitBalance(query: *Query) void {
    query.ref();
    defer query.deref();
    var mysql_query = MySQLQuery.init(query, allocator, 0);
    _ = &mysql_query;
}

// Control 3 — .ref() but no init call following.  Should NOT fire.
pub fn keepRef(query: *Query) void {
    query.ref();
    _ = query;
}
