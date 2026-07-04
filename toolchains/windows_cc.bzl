# Windows PE compilation and linking rules using the hermetic LLVM toolchain.
#
# These replace bash/cmd_exe genrules with proper Buck2 actions that:
#   - work natively on Windows without any shell dependency
#   - give Buck2 proper dependency tracking (each file is a separate action)
#   - are fully incremental (only recompile changed sources)
#
# Public surface:
#   WinCCInfo             — provider carrying tool paths + sysroot flags
#   win_cc_toolchain_info — rule that creates a WinCCInfo from llvm_dist + msvc_sysroot
#   win_cc_compile        — helper: compile one C/C++/asm source → .obj artifact
#   win_cc_link_dll       — helper: link objs → .dll + import .lib artifacts
#   win_cc_link_exe       — helper: link objs/libs → .exe artifact

# ── Provider ──────────────────────────────────────────────────────────────────

WinCCInfo = provider(
    doc = """
    Hermetic Windows cross-compilation toolchain.

    Carries cmd_args pointing at the LLVM binaries and pre-built
    -imsvc / /LIBPATH flags derived from the xwin MSVC sysroot.
    Pass this provider around to compilation/link helpers instead of
    hard-coding paths.
    """,
    fields = {
        # cmd_args that expand to the LLVM binary paths
        "clang_cl": provider_field(typing.Any),
        "lld_link":  provider_field(typing.Any),
        "llvm_lib":  provider_field(typing.Any),
        # sysroot-derived compiler include flags (list of cmd_args)
        # These add the CRT / Windows SDK header trees to the include path
        # without pulling in any default libraries.
        "include_flags": provider_field(list),
        # sysroot-derived linker library-path flags (list of cmd_args)
        "lib_flags": provider_field(list),
    },
)

# ── win_cc_toolchain_info rule ────────────────────────────────────────────────

def _win_cc_toolchain_info_impl(ctx):
    llvm    = ctx.attrs.llvm_dist[DefaultInfo].default_outputs[0]
    sysroot = ctx.attrs.msvc_sysroot[DefaultInfo].default_outputs[0]

    return [
        DefaultInfo(),
        WinCCInfo(
            clang_cl  = cmd_args(llvm, format = "{}/bin/clang-cl.exe"),
            lld_link  = cmd_args(llvm, format = "{}/bin/lld-link.exe"),
            llvm_lib  = cmd_args(llvm, format = "{}/bin/llvm-lib.exe"),
            include_flags = [
                cmd_args(sysroot, format = "-imsvc {}/crt/include"),
                cmd_args(sysroot, format = "-imsvc {}/sdk/include/ucrt"),
                cmd_args(sysroot, format = "-imsvc {}/sdk/include/um"),
                cmd_args(sysroot, format = "-imsvc {}/sdk/include/shared"),
                cmd_args(sysroot, format = "-imsvc {}/sdk/include/winrt"),
            ],
            lib_flags = [
                cmd_args(sysroot, format = "/LIBPATH:{}/crt/lib/x86_64"),
                cmd_args(sysroot, format = "/LIBPATH:{}/sdk/lib/um/x86_64"),
                cmd_args(sysroot, format = "/LIBPATH:{}/sdk/lib/ucrt/x86_64"),
            ],
        ),
    ]

win_cc_toolchain_info = rule(
    doc = "Exposes a WinCCInfo provider from prebuilt LLVM + xwin sysroot targets.",
    impl = _win_cc_toolchain_info_impl,
    attrs = {
        "llvm_dist":    attrs.exec_dep(providers = [DefaultInfo]),
        "msvc_sysroot": attrs.exec_dep(providers = [DefaultInfo]),
    },
)

# ── Action helpers ────────────────────────────────────────────────────────────
# These are plain Starlark functions (not rules) intended to be called from
# rule implementations.  Each schedules one Buck2 action and returns the
# output artifact(s).

def win_cc_compile(
        actions,
        tools,
        src,
        out_name,
        extra_flags = [],
        include_sysroot = True):
    """Compile one C / C++ / asm source file to a Windows .obj.

    Args:
        actions:         ctx.actions from the calling rule.
        tools:           WinCCInfo provider.
        src:             Source artifact (attrs.source or declared artifact).
        out_name:        Base name used for the output file (<out_name>.obj).
        extra_flags:     Additional compiler flags (e.g. -ffreestanding).
        include_sysroot: When True, add tools.include_flags (MSVC / SDK headers).
                         Set False for fully freestanding code that never
                         includes standard headers.
    Returns:
        The .obj artifact.
    """
    obj = actions.declare_output(out_name + ".obj")

    cmd = cmd_args()
    cmd.add(tools.clang_cl)
    cmd.add("--target=x86_64-pc-windows-msvc")
    cmd.add(extra_flags)
    if include_sysroot:
        cmd.add(tools.include_flags)
    cmd.add("-c", src)
    cmd.add("-o", obj.as_output())

    actions.run(cmd, category = "clang_cl", identifier = out_name)
    return obj


def win_cc_link_dll(
        actions,
        tools,
        out_dll,
        out_lib,
        objs,
        def_file,
        extra_link_flags = [],
        lib_sysroot = False):
    """Link object files into a Windows DLL + import library.

    Args:
        actions:          ctx.actions from the calling rule.
        tools:            WinCCInfo provider.
        out_dll:          Output DLL filename (e.g. "ntdll.dll").
        out_lib:          Output import-lib filename (e.g. "ntdll.lib").
        objs:             List of .obj artifacts to link.
        def_file:         Module-definition (.def) source artifact.
        extra_link_flags: Additional lld-link flags.
        lib_sysroot:      When True, add tools.lib_flags (CRT / SDK lib paths).
    Returns:
        (dll_artifact, implib_artifact)
    """
    dll = actions.declare_output(out_dll)
    lib = actions.declare_output(out_lib)

    cmd = cmd_args()
    cmd.add(tools.lld_link)
    cmd.add("/dll", "/machine:x64")
    cmd.add(extra_link_flags)
    if lib_sysroot:
        cmd.add(tools.lib_flags)
    cmd.add(cmd_args(def_file,        format = "/def:{}"))
    cmd.add(cmd_args(dll.as_output(), format = "/out:{}"))
    cmd.add(cmd_args(lib.as_output(), format = "/implib:{}"))
    cmd.add(objs)

    actions.run(cmd, category = "lld_link_dll", identifier = out_dll)
    return (dll, lib)


def win_cc_link_exe(
        actions,
        tools,
        out_exe,
        objs,
        extra_link_flags = [],
        lib_sysroot = False):
    """Link object files (and import libs) into a Windows EXE.

    Args:
        actions:          ctx.actions from the calling rule.
        tools:            WinCCInfo provider.
        out_exe:          Output executable filename (e.g. "init.exe").
        objs:             List of .obj and .lib artifacts to link.
        extra_link_flags: Additional lld-link flags.
        lib_sysroot:      When True, add tools.lib_flags (CRT / SDK lib paths).
    Returns:
        The .exe artifact.
    """
    exe = actions.declare_output(out_exe)

    cmd = cmd_args()
    cmd.add(tools.lld_link)
    cmd.add("/machine:x64")
    cmd.add(extra_link_flags)
    if lib_sysroot:
        cmd.add(tools.lib_flags)
    cmd.add(cmd_args(exe.as_output(), format = "/out:{}"))
    cmd.add(objs)

    actions.run(cmd, category = "lld_link_exe", identifier = out_exe)
    return exe
