const std = @import("std");

pub fn build(b: *std.Build) void {
    // Define the supported targets
    const targets = [_]std.zig.CrossTarget{
        .{ .cpu_arch = .x86_64, .os_tag = .macos },
        .{ .cpu_arch = .aarch64, .os_tag = .macos },
        .{ .cpu_arch = .x86_64, .os_tag = .windows },
        .{ .cpu_arch = .aarch64, .os_tag = .windows },
        .{ .cpu_arch = .x86_64, .os_tag = .linux },
        .{ .cpu_arch = .aarch64, .os_tag = .linux },
    };

    // Standard optimization options
    const optimize = b.standardOptimizeOption(.{});

    for (targets) |target| {
        const lib = b.addStaticLibrary(.{
            .name = "QompaSSL",
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        });

        // Install the library
        b.installArtifact(lib);

        const exe = b.addExecutable(.{
            .name = "QompaSSL",
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        });

        // Install the executable
        b.installArtifact(exe);

        // Run step (only for native target)
        if (target.isNative()) {
            const run_cmd = b.addRunArtifact(exe);
            run_cmd.step.dependOn(b.getInstallStep());

            if (b.args) |args| {
                run_cmd.addArgs(args);
            }

            const run_step = b.step("run", "Run the app");
            run_step.dependOn(&run_cmd.step);
        }

        // Unit tests
        const lib_unit_tests = b.addTest(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        });
        const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

        const exe_unit_tests = b.addTest(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

        // Test step
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_lib_unit_tests.step);
        test_step.dependOn(&run_exe_unit_tests.step);
    }
}
