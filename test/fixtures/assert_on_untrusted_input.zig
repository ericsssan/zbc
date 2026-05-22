// assert-on-untrusted-input — tigerbeetle/tigerbeetle#3709 +
// #3726 + #2980 class.  `assert(...)` in a parser/decoder fn
// against untrusted-input parameters panics on crafted bytes.

const std = @import("std");

fn assert(_: bool) void {}

const Message = struct {
    size: usize,
    kind: u8,
};

// Bug — fires on `assert(buffer[0] == 0xFF)`.
pub fn parse_header_buggy(buffer: []const u8) !void {
    assert(buffer[0] == 0xFF);
}

// Bug — slice param + assert references it.
pub fn decode_frame_buggy(frame: []const u8) !void {
    assert(frame.len >= 8);
    assert(frame[0] == 0xCE);
}

// Control — structured *Message wrapper (NOT a slice).  The rule
// excludes these because typed wrappers are too commonly used for
// internally-constructed-and-validated values.
pub fn decode_message_internal(message: *Message) !void {
    assert(message.size > 0);
    assert(message.kind < 16);
}

// Control — fn renamed/refactored to `parse_header_fixed`; uses
// explicit `if` instead of assert.  Should NOT fire.
pub fn parse_header_fixed(buffer: []const u8) !void {
    if (buffer[0] != 0xFF) return error.InvalidMagic;
}

// Control — assert references self.field (internal invariant),
// not the buffer.  Should NOT fire.
const State = struct {
    counter: usize,

    pub fn parse_chunk(self: *State, buffer: []const u8) !void {
        _ = buffer;
        assert(self.counter > 0);
    }
};

// Control — non-parser fn name + no byte-like params.  Should
// NOT fire.
pub fn tick(state: *State) void {
    assert(state.counter > 0);
    state.counter -= 1;
}
