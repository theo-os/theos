const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const init = b.addExecutable("tinit", "src/init.zig");
    init.setTarget(target);
    init.setBuildMode(mode);
    init.install();

    const dhclient = b.addExecutable("dhclient", "src/dhclient.zig");
    dhclient.setTarget(target);
    dhclient.setBuildMode(mode);
    dhclient.linkLibC();
    dhclient.install();

    const dhcp_tests = b.addTest("src/dhclient.zig");
    dhcp_tests.setTarget(target);
    dhcp_tests.setBuildMode(mode);
    dhcp_tests.linkLibC();

    const runTests = b.step("test", "Run tests");
    runTests.dependOn(&dhcp_tests.step);
}
