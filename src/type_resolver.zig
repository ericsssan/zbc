//! Bridge between zbc and the type engine.
//! Re-exports TypeContext + TypeResolver for use by lib.zig / main.zig.

const engine = @import("type_engine");

pub const TypeContext = engine.TypeContext;
pub const TypeResolver = engine.TypeResolver;
pub const clearToolchainCacheForTesting = engine.clearToolchainCacheForTesting;
