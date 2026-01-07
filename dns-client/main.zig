const std = @import("std");
const dns = @import("models/request.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const domain: []const u8 = "uauth.com";
    const dns_request = try dns.Request.init(domain, dns.Type.A, dns.Qclass.IN);

    const send = try dns_request.Send(allocator, "1.1.1.1");

    const response = try dns.DnsResourceRecord.initFromResponse(allocator, send);
    std.debug.print("Domain: {s} - {s}\n", .{ response.name, response.rdata });
}
