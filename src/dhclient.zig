const std = @import("std");
const c = @cImport({
    @cInclude("net/if.h");
    @cInclude("linux/sockios.h");
    @cInclude("sys/ioctl.h");
    @cInclude("sys/types.h");
    @cInclude("ifaddrs.h");
});

pub const SocketFlags = enum(u32) {
    SIOCGIFCONF = 0x8912,
    SIOCGIFFLAGS = 0x8913,
};

pub const Interface = struct {
    name: []const u8,
    sock: std.os.socket_t,

    const Self = @This();

    pub fn setIp(self: *Self, ip: [4]u8, mask: [4]u8, gateway: [4]u8) !void {
        var ifreq: c.ifreq = undefined;
        var rt: c.rtentry = undefined;

        // set ip
        try std.mem.copy(u8, ifreq.ifr_name[0..], self.name);
        ifreq.ifr_addr.sa_family = c.AF_INET;
        try std.mem.copy(u8, ifreq.ifr_addr.sa_data[0..], ip[0..]);
        c.ioctl(self.sock, c.SIOCSIFADDR, &ifreq);

        // set mask
        try std.mem.copy(u8, ifreq.ifr_name[0..], self.name);
        ifreq.ifr_addr.sa_family = c.AF_INET;
        try std.mem.copy(u8, ifreq.ifr_addr.sa_data[0..], mask[0..]);
        c.ioctl(self.sock, c.SIOCSIFNETMASK, &ifreq);

        // set gateway
        try std.mem.copy(u8, ifreq.ifr_name[0..], self.name);
        ifreq.ifr_addr.sa_family = c.AF_INET;
        try std.mem.copy(u8, ifreq.ifr_addr.sa_data[0..], gateway[0..]);
        c.ioctl(self.sock, c.SIOCSIFDSTADDR, &ifreq);

        // set route
        try std.mem.copy(u8, ifreq.ifr_name[0..], self.name);
        rt.rt_dev = ifreq.ifr_name[0];
        rt.rt_flags = c.RTF_UP | c.RTF_GATEWAY;
        rt.rt_metric = 0;
        rt.rt_dst.sa_family = c.AF_INET;
        rt.rt_gateway.sa_family = c.AF_INET;
        try std.mem.copy(u8, rt.rt_gateway.sa_data[0..], gateway[0..]);
        c.ioctl(self.sock, c.SIOCADDRT, &rt);

        // set interface up
        try std.mem.copy(u8, ifreq.ifr_name[0..], self.name);
        ifreq.ifr_ifru.ifru_flags = c.IFF_UP | c.IFF_RUNNING;

        c.ioctl(self.sock, c.SIOCSIFFLAGS, &ifreq);
    }

    pub fn setDNS(self: *Self, dns: [4]u8) !void {
        var ifreq: c.ifreq = undefined;

        // set dns
        try std.mem.copy(u8, ifreq.ifr_name[0..], self.name);
        ifreq.ifr_addr.sa_family = c.AF_INET;
        try std.mem.copy(u8, ifreq.ifr_addr.sa_data[0..], dns[0..]);
        c.ioctl(self.sock, c.SIOCSIFDSTADDR, &ifreq);
    }
};

pub fn getInterface(name: []u8) !Interface {
    var ifreq: c.ifreq = undefined;
    // ifreq.ifr_ifrn.ifrn_name = name[0..];

    const sock = try std.os.socket(c.AF_INET, c.SOCK_DGRAM, 0);
    defer std.os.close(sock);

    var res = c.ioctl(sock, c.SIOCGIFFLAGS, &ifreq);

    if (res != 0) return error.InterfaceNotFound;

    if (ifreq.ifr_ifru.ifru_flags & c.IFF_UP == 0) {
        return error.InterfaceNotUp;
    }

    return Interface{
        .name = name,
        .sock = sock,
    };
}

pub fn getOwnedInterfaces(allocator: std.mem.Allocator) !std.ArrayList(Interface) {
    var interfaces = std.ArrayList(Interface).init(allocator);

    // use c.ifaddrs
    var ifaddrs: [*c]c.ifaddrs = undefined;
    var res = c.getifaddrs(&ifaddrs);
    if (res != 0) {
        return error.GetIfAddrsFailed;
    }

    while (ifaddrs != null) {
        const name = std.mem.span(ifaddrs.*.ifa_name);
        std.debug.print("name: {s}\n", .{name});
        const interface = try getInterface(name);
        try interfaces.append(interface);

        ifaddrs = ifaddrs.*.ifa_next;
    }

    return interfaces;
}

test "get interfaces" {
    // enp38s0
    const interfaces = try getOwnedInterfaces(std.testing.allocator);
    defer interfaces.deinit();

    for (interfaces.items) |interface| {
        std.debug.print("interface: {s}\n", .{interface.name});
    }
}
