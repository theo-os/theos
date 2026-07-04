# Rule definitions for building freestanding native init components.

load("@toolchains//:windows_cc.bzl", "WinCCInfo", "win_cc_compile", "win_cc_link_dll", "win_cc_link_exe")

def _native_init_impl(ctx):
    tools = ctx.attrs.win_cc[WinCCInfo]

    # Flags for freestanding C code (no CRT, no stack protector, no builtins).
    # These files don't include any standard headers, so include_sysroot=False.
    freestanding = ["-ffreestanding", "-fno-stack-protector", "-fno-builtin", "-GS-"]

    # ── Compile ───────────────────────────────────────────────────────────────
    init_obj = win_cc_compile(
        ctx.actions, tools, ctx.attrs.init_c, "init",
        extra_flags = freestanding, include_sysroot = False,
    )
    child_obj = win_cc_compile(
        ctx.actions, tools, ctx.attrs.child_c, "child",
        extra_flags = freestanding, include_sysroot = False,
    )
    init_reloc_obj = win_cc_compile(
        ctx.actions, tools, ctx.attrs.init_reloc_c, "init_reloc",
        extra_flags = freestanding, include_sysroot = False,
    )
    ntdll_reloc_obj = win_cc_compile(
        ctx.actions, tools, ctx.attrs.ntdll_reloc_c, "ntdll_reloc",
        extra_flags = freestanding, include_sysroot = False,
    )
    # Assembly stubs — clang-cl compiles these as MASM-style asm
    syscall_stubs_obj = win_cc_compile(
        ctx.actions, tools, ctx.attrs.syscall_stubs_s, "syscall_stubs",
        include_sysroot = False,
    )
    ntdll_stubs_obj = win_cc_compile(
        ctx.actions, tools, ctx.attrs.ntdll_stubs_s, "ntdll_stubs",
        include_sysroot = False,
    )

    # ── Link ntdll.dll + ntdll.lib ────────────────────────────────────────────
    # /noentry  — DLL has no DllMain
    # /nodefaultlib — fully freestanding, no CRT
    # /base     — fixed preferred base address (matches Windows kernel expectation)
    ntdll_dll, ntdll_lib = win_cc_link_dll(
        ctx.actions, tools,
        out_dll = "ntdll.dll",
        out_lib = "ntdll.lib",
        objs    = [ntdll_stubs_obj, ntdll_reloc_obj],
        def_file = ctx.attrs.ntdll_def,
        extra_link_flags = ["/noentry", "/nodefaultlib", "/base:0x140000000"],
    )

    # ── Link init.exe ─────────────────────────────────────────────────────────
    # Links against the ntdll import library built above.
    init_exe = win_cc_link_exe(
        ctx.actions, tools,
        out_exe = "init.exe",
        objs    = [init_obj, init_reloc_obj, ntdll_lib],
        extra_link_flags = [
            "/entry:start", "/subsystem:native", "/nodefaultlib", "/fixed:no",
        ],
    )

    # ── Link child.exe ────────────────────────────────────────────────────────
    child_exe = win_cc_link_exe(
        ctx.actions, tools,
        out_exe = "child.exe",
        objs    = [child_obj, init_reloc_obj, ntdll_lib],
        extra_link_flags = [
            "/entry:start", "/subsystem:native", "/nodefaultlib", "/fixed:no",
        ],
    )

    # Expose sub_targets matching the original genrule interface so that
    # downstream $(location //userspace/native_init:native_init[init]) etc.
    # continue to work without changing any other BUCK files.
    return [
        DefaultInfo(
            default_output = init_exe,
            sub_targets = {
                "init":      [DefaultInfo(default_output = init_exe)],
                "child":     [DefaultInfo(default_output = child_exe)],
                "ntdll_dll": [DefaultInfo(default_output = ntdll_dll)],
                "ntdll_lib": [DefaultInfo(default_output = ntdll_lib)],
            },
        ),
    ]

native_init = rule(
    impl = _native_init_impl,
    attrs = {
        # C source files
        "init_c":          attrs.source(),
        "child_c":         attrs.source(),
        "init_reloc_c":    attrs.source(),
        "ntdll_reloc_c":   attrs.source(),
        # Assembly stubs
        "syscall_stubs_s": attrs.source(),
        "ntdll_stubs_s":   attrs.source(),
        # Module-definition file for ntdll.dll
        "ntdll_def":       attrs.source(),
        # WinCCInfo provider from toolchains//:win_cc_tools
        "win_cc":          attrs.dep(providers = [WinCCInfo]),
    },
)
