const std = @import("std");
const os = std.os.linux;
const time = std.time;

// Main Request header
pub const Request = struct {
    header: DnsRequestHeader, // serialize with [12]u8: @bitCast(header)
    question: ?DnsRequestQuestion,
    answer: ?DnsResourceRecord,
    authority: ?DnsResourceRecord,
    additional: ?DnsResourceRecord,

    pub fn init(domain: []const u8, qtype: Type, qclass: Qclass) !Request {
        if (qtype != Type.A) return error.NotImplemented;
        return .{
            .header = @bitCast(try DnsRequestHeader.init()),
            .question = DnsRequestQuestion.init(domain, qtype, qclass),
            .answer = null,
            .authority = null,
            .additional = null,
        };
    }

    pub fn Send(self: Request, allocator: std.mem.Allocator, server: []const u8) ![]const u8 {
        //_ = allocator;
        // initialize socket
        const sockfd = os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC, 0);
        defer _ = os.close(@intCast(sockfd));

        const addr = try std.net.Address.resolveIp(server, 53);
        const sockaddr_ptr = &addr.any;
        const sockaddr_len = addr.getOsSockLen();

        // serialize request
        const msg = try self.serialize(allocator);
        defer allocator.free(msg);

        const send_bytes = os.sendto(
            @intCast(sockfd),
            msg.ptr,
            msg.len,
            0,
            sockaddr_ptr,
            sockaddr_len,
        );

        var buf: [512]u8 = undefined;
        var src_addr: std.net.Address = undefined;
        var src_len: os.socklen_t = @sizeOf(std.net.Address);

        const recv_bytes = os.recvfrom(
            @intCast(sockfd),
            &buf,
            buf.len,
            0,
            &src_addr.any,
            &src_len,
        );

        if (recv_bytes < 0) return error.ReceiveFailed;
        const response = try allocator.dupe(u8, buf[0..@intCast(recv_bytes)]);

        std.debug.print("{d}: answer_bytes={d}\n", .{ time.milliTimestamp(), recv_bytes });
        if (send_bytes < 0) return error.SendFailed;
        return response;
    }

    fn serialize(self: Request, allocator: std.mem.Allocator) ![]const u8 {
        const questionField = self.question orelse return error.UndefinedQuestion;
        var buf = std.ArrayList(u8).empty;

        // Header (12 bytes)
        const header_bytes = self.header.toBytes();
        try buf.appendSlice(allocator, &header_bytes);

        //// Question: QNAME
        const qname = try self.encodeName(allocator);
        defer allocator.free(qname);
        try buf.appendSlice(allocator, qname);

        //// Question: QTYPE (2 bytes)
        var qt: [2]u8 = undefined;
        // swap endian
        std.mem.writeInt(u16, &qt, @intFromEnum(questionField.qtype), .big);
        try buf.appendSlice(allocator, &qt);

        // Question: QCLASS (2 bytes)
        var qc: [2]u8 = undefined;
        // swap endian
        std.mem.writeInt(u16, &qc, @intFromEnum(questionField.qclass), .big);
        try buf.appendSlice(allocator, &qc);

        return buf.toOwnedSlice(allocator);
    }

    fn encodeName(self: Request, allocator: std.mem.Allocator) ![]const u8 {
        const questionField = self.question orelse return error.UndefinedQuestion;
        var buf = std.ArrayList(u8).empty;
        // split
        var parts = std.mem.tokenizeScalar(u8, questionField.qname, '.');

        while (parts.next()) |part| {
            //const len_str = try std.fmt.allocPrint(allocator, "{}", .{part.len});
            //defer allocator.free(len_str);

            try buf.append(allocator, @intCast(part.len));
            try buf.appendSlice(allocator, part);
        }
        // add nullbyte
        try buf.append(allocator, 0);
        return try buf.toOwnedSlice(allocator);
    }
};
//

pub const Opcode = enum(u4) {
    query = 0, // Standard query
    iquery = 1, // Inverse query (obsolete)
    status = 2, // Server status request
    notify = 4, // Notify request
    update = 5, // Dynamic dns update
};

pub const Rcode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3,
    not_implemented = 4,
    refused = 5,
};

pub const Type = enum(u16) {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,

    // QTypes
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    @"*" = 255,
};

pub const Qclass = enum(u16) {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
};

pub const DnsRequestHeader = packed struct {
    id: u16, // ID to identify request/response | unique 16bit field
    qr: u1, // 0 = query, 1 = response
    opcode: Opcode, // Type of dns query | see enum
    aa: u1, // if the answer is authoritative | set in response
    tc: u1, // is the message truncated | client will retry with TCP if packet exceededs 512 bytes
    rd: u1, // recursion desired
    ra: u1, // is recursion available
    z: u3, // reserved | always 0
    rcode: Rcode, // return code
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,

    fn generateRandomId() !u16 {
        var prng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            try std.posix.getrandom(std.mem.asBytes(&seed));
            break :blk seed;
        });
        return std.Random.int(prng.random(), u16);
    }

    pub fn init() !DnsRequestHeader {
        return .{
            .id = try generateRandomId(),
            .qr = 0,
            .opcode = Opcode.query,
            .aa = 0,
            .tc = 0,
            .rd = 1,
            .ra = 0,
            .z = 0,
            .rcode = Rcode.no_error,
            .qdcount = 1,
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        };
    }

    pub fn toBytes(self: DnsRequestHeader) [12]u8 {
        var out: [12]u8 = undefined;

        std.mem.writeInt(u16, out[0..2], self.id, .big);

        var flags: u16 = 0;
        flags |= @as(u16, self.qr) << 15;
        flags |= @as(u16, @intFromEnum(self.opcode)) << 11;
        flags |= @as(u16, self.aa) << 10;
        flags |= @as(u16, self.tc) << 9;
        flags |= @as(u16, self.rd) << 8;
        flags |= @as(u16, self.ra) << 7;
        flags |= @as(u16, self.z) << 4;
        flags |= @as(u16, @intFromEnum(self.rcode));

        std.mem.writeInt(u16, out[2..4], flags, .big);

        // counts are always zero in a request
        std.mem.writeInt(u16, out[4..6], self.qdcount, .big);
        std.mem.writeInt(u16, out[6..8], self.ancount, .big);
        std.mem.writeInt(u16, out[8..10], self.nscount, .big);
        std.mem.writeInt(u16, out[10..12], self.arcount, .big);

        return out;
    }

    pub fn initFromResponse(buf: []const u8) !DnsRequestHeader {
        if (buf.len < 12) return error.Truncated;
        const id = std.mem.readInt(u16, buf[0..2], .big);
        const flags = std.mem.readInt(u16, buf[2..4], .big);

        // prepare cast
        const opc: u4 = @intCast((flags >> 11) & 0xf);
        const rco: u4 = @intCast((flags & 0xf));

        return DnsRequestHeader{
            .id = id,
            .qr = @intCast((flags >> 15) & 0x1),
            .opcode = @enumFromInt(opc),
            .aa = @intCast((flags >> 10) & 0x1),
            .tc = @intCast((flags >> 9) & 0x1),
            .rd = @intCast((flags >> 8) & 0x1),
            .ra = @intCast((flags >> 7) & 0x1),
            .z = @intCast((flags >> 4) & 0x7),
            .rcode = @enumFromInt(rco),
            .qdcount = std.mem.readInt(u16, buf[4..6], .big),
            .ancount = std.mem.readInt(u16, buf[6..8], .big),
            .nscount = std.mem.readInt(u16, buf[8..10], .big),
            .arcount = std.mem.readInt(u16, buf[10..12], .big),
        };
    }
};

pub const DnsResourceRecord = struct {
    name: []const u8 = undefined,
    rtype: Type = undefined,
    class: Qclass = undefined,
    ttl: u32 = 0,
    rdlength: u16 = 0, // lenght needs to match rdata.len
    rdata: []const u8 = undefined,

    pub fn init(name: []const u8, rtype: Type, class: Qclass, ttl: u32, rdata: []const u8) DnsResourceRecord {
        return .{
            .name = name.ptr,
            .rtype = rtype,
            .class = class,
            .ttl = ttl,
            .rdlength = rdata.len,
            .rdata = rdata.ptr,
        };
    }

    fn decodeName(allocator: std.mem.Allocator, buf: []const u8, pos: *usize) ![]const u8 {
        var labels = std.ArrayList(u8).empty;
        defer labels.deinit(allocator);

        const max_recursion = 10;
        var recursion_count: u8 = 0;
        var current_pos: usize = pos.*;

        while (true) {
            if (current_pos >= buf.len) return error.Truncated;

            // get length
            const length = buf[current_pos];

            if ((length & 0xC0) == 0xC0) {
                // pointer: nex tbyte + lower 6 bits
                if (current_pos + 1 >= buf.len) return error.Truncated;

                const offset: u16 = @intCast(length & 0x3F);
                const current_tmp: u16 = @intCast(buf[current_pos + 1]);
                const ptr_offset: u16 = (offset << 8) | current_tmp;
                if (ptr_offset >= buf.len) return error.Truncated;
                if (recursion_count >= max_recursion) return error.TooManyRecursions;

                recursion_count += 1;

                var pointer_offset: usize = @intCast(ptr_offset);
                const pointed_name = try decodeName(allocator, buf, &pointer_offset);
                try labels.appendSlice(allocator, pointed_name);
                current_pos += 2;
                break;
            } else if (length == 0) {
                current_pos += 1;
                break;
            } else {
                current_pos += 1;
                if (current_pos + length > buf.len) return error.Truncated;
                try labels.appendSlice(allocator, buf[current_pos .. current_pos + length]);
                current_pos += length;
                try labels.append(allocator, '.');
            }
        }

        pos.* = current_pos;
        if (labels.items.len > 0 and labels.items[labels.items.len - 1] == '.') _ = labels.pop();
        return allocator.dupe(u8, labels.items);
    }

    fn decodeRdata(allocator: std.mem.Allocator, rdata: []const u8) ![]u8 {
        if (rdata.len != 4) return error.InvalidRdata;

        var buf: [16]u8 = undefined;
        const ip = try std.fmt.bufPrint(buf[0..], "{}.{}.{}.{}", .{ rdata[0], rdata[1], rdata[2], rdata[3] });
        return try allocator.dupe(u8, buf[0..ip.len]);
    }

    pub fn initFromResponse(allocator: std.mem.Allocator, buf: []const u8) !DnsResourceRecord {
        var pos: usize = 12;

        // decode qname (pos is already updated inside)
        const header = try DnsRequestHeader.initFromResponse(buf);
        var i: usize = 0;
        while (i < header.qdcount) : (i += 1) {
            _ = try decodeName(allocator, buf, &pos);
            pos += 2;
            pos += 2;
        }

        const qname = try decodeName(allocator, buf, &pos);

        // TYPE: 2 bytes
        const rtype_tmp: *const [2]u8 = @ptrCast(&buf[pos]);
        const rtype: Type = @enumFromInt(std.mem.readInt(u16, rtype_tmp, .big));
        pos += 2;

        // CLASS: 2 bytes
        const class_tmp: *const [2]u8 = @ptrCast(&buf[pos]);
        const class: Qclass = @enumFromInt(std.mem.readInt(u16, class_tmp, .big));
        pos += 2;

        // TTL: 4 bytes
        const ttl_tmp: *const [4]u8 = @ptrCast(&buf[pos]);
        const ttl: u32 = std.mem.readInt(u32, ttl_tmp, .big);
        pos += 4;

        // RDLENGTH: 2 bytes
        const rdlength_tmp: *const [2]u8 = @ptrCast(&buf[pos]);
        const rdlength: u16 = std.mem.readInt(u16, rdlength_tmp, .big);
        pos += 2;

        // RDATA: rdlength bytes
        const rdlength_tmp_usize: usize = @intCast(rdlength);
        if (pos + rdlength_tmp_usize > buf.len) return error.Truncated;
        const rdata: []const u8 = buf[pos .. pos + rdlength_tmp_usize];
        pos += rdlength_tmp_usize;

        defer allocator.free(qname);
        return .{
            .name = try allocator.dupe(u8, qname),
            .rtype = rtype,
            .class = class,
            .ttl = ttl,
            .rdlength = rdlength,
            .rdata = try decodeRdata(allocator, rdata),
        };
    }
};

pub const DnsRequestQuestion = struct {
    qname: []const u8,
    qtype: Type,
    qclass: Qclass,

    pub fn init(domain: []const u8, qtype: Type, qclass: Qclass) DnsRequestQuestion {
        return .{
            .qname = domain,
            .qtype = qtype,
            .qclass = qclass,
        };
    }
};
