# Hermetic CXX toolchain for Theos
#
# Uses a prebuilt LLVM distribution (clang-cl, lld-link, llvm-lib) plus
# an xwin-splatted MSVC sysroot (CRT headers/libs + Windows SDK headers/libs)
# to produce a fully hermetic x86_64-pc-windows-msvc CXX toolchain that does
# not depend on any system Visual Studio installation.
#
# Architecture:
#   llvm_win64 (http_archive)     → LLVM binaries (clang-cl, lld-link, …)
#   msvc_sysroot (genrule/xwin)   → MSVC sysroot (crt/, sdk/)
#   hermetic_cxx_toolchain (rule) → CxxToolchainInfo combining both
#
# xwin sysroot layout after `xwin splat --output <dir>`:
#   <dir>/crt/include/
#   <dir>/crt/lib/x86_64/
#   <dir>/sdk/include/{ucrt,um,shared,winrt}/
#   <dir>/sdk/lib/{um,ucrt}/x86_64/

load(
    "@prelude//cxx:cxx_toolchain_types.bzl",
    "BinaryUtilitiesInfo",
    "CCompilerInfo",
    "CvtresCompilerInfo",
    "CxxCompilerInfo",
    "CxxInternalTools",
    "CxxPlatformInfo",
    "CxxToolchainInfo",
    "DepTrackingMode",
    "LinkerInfo",
    "LinkerType",
    "PicBehavior",
    "RcCompilerInfo",
    "RuntimeDependencyHandling",
    "ShlibInterfacesMode",
)
load("@prelude//cxx:headers.bzl", "HeaderMode")
load("@prelude//cxx:linker.bzl", "is_pdb_generated")
load("@prelude//linking:link_info.bzl", "LinkOrdering", "LinkStyle")
load("@prelude//linking:lto.bzl", "LtoMode")

def _hermetic_cxx_toolchain_impl(ctx: AnalysisContext) -> list[Provider]:
    # Root of the extracted LLVM prebuilt archive (from http_archive).
    llvm = ctx.attrs.llvm_dist[DefaultInfo].default_outputs[0]

    # Root of the xwin-splatted MSVC sysroot (from genrule).
    sysroot = ctx.attrs.msvc_sysroot[DefaultInfo].default_outputs[0]

    # ── Compiler / linker / archiver binary paths ────────────────────────────
    # cmd_args(artifact, format="…{}…") expands to the resolved artifact path.
    clang_cl = cmd_args(llvm, format = "{}/bin/clang-cl.exe")
    lld_link  = cmd_args(llvm, format = "{}/bin/lld-link.exe")
    llvm_lib  = cmd_args(llvm, format = "{}/bin/llvm-lib.exe")
    llvm_nm   = cmd_args(llvm, format = "{}/bin/llvm-nm.exe")
    llvm_rc   = cmd_args(llvm, format = "{}/bin/llvm-rc.exe")

    # ── Sysroot-derived include flags ────────────────────────────────────────
    # clang-cl accepts -imsvc <dir> to add an MSVC-style include search path.
    sysroot_include_flags = [
        cmd_args(sysroot, format = "-imsvc {}/crt/include"),
        cmd_args(sysroot, format = "-imsvc {}/sdk/include/ucrt"),
        cmd_args(sysroot, format = "-imsvc {}/sdk/include/um"),
        cmd_args(sysroot, format = "-imsvc {}/sdk/include/shared"),
        cmd_args(sysroot, format = "-imsvc {}/sdk/include/winrt"),
    ]

    # ── Sysroot-derived lib-path flags ───────────────────────────────────────
    # lld-link / link.exe consume /LIBPATH:<dir> to add library search paths.
    sysroot_lib_flags = [
        cmd_args(sysroot, format = "/LIBPATH:{}/crt/lib/x86_64"),
        cmd_args(sysroot, format = "/LIBPATH:{}/sdk/lib/um/x86_64"),
        cmd_args(sysroot, format = "/LIBPATH:{}/sdk/lib/ucrt/x86_64"),
    ]

    def _compiler(binary):
        return RunInfo(args = [binary])

    return [
        DefaultInfo(),
        CxxToolchainInfo(
            internal_tools = ctx.attrs._internal_tools[CxxInternalTools],

            # ── Linker ──────────────────────────────────────────────────────
            linker_info = LinkerInfo(
                linker            = _compiler(lld_link),
                linker_flags      = sysroot_lib_flags + ctx.attrs.link_flags,
                post_linker_flags = ctx.attrs.post_link_flags,
                archiver          = _compiler(llvm_lib),
                archiver_type     = "windows",
                archiver_supports_argfiles = True,
                generate_linker_maps      = False,
                lto_mode                  = LtoMode("none"),
                type                      = LinkerType("windows"),
                link_binaries_locally     = True,
                link_libraries_locally    = True,
                archive_objects_locally   = True,
                use_archiver_flags        = True,
                static_dep_runtime_ld_flags       = [],
                static_pic_dep_runtime_ld_flags   = [],
                shared_dep_runtime_ld_flags       = [],
                independent_shlib_interface_linker_flags = [],
                shlib_interfaces                  = ShlibInterfacesMode("disabled"),
                link_style                        = LinkStyle(ctx.attrs.link_style),
                link_weight                       = 1,
                binary_extension                  = "exe",
                object_file_extension             = "obj",
                shared_library_name_default_prefix = "",
                shared_library_name_format         = "{}.dll",
                shared_library_versioned_name_format = "{}.dll",
                static_library_extension           = "lib",
                force_full_hybrid_if_capable       = False,
                is_pdb_generated = is_pdb_generated(LinkerType("windows"), ctx.attrs.link_flags),
                link_ordering = ctx.attrs.link_ordering,
            ),

            # ── Binary utilities ─────────────────────────────────────────────
            bolt_enabled = False,
            binary_utilities_info = BinaryUtilitiesInfo(
                nm      = _compiler(llvm_nm),
                objcopy = _compiler(cmd_args(llvm, format = "{}/bin/llvm-objcopy.exe")),
                objdump = _compiler(cmd_args(llvm, format = "{}/bin/llvm-objdump.exe")),
                ranlib  = _compiler(cmd_args(llvm, format = "{}/bin/llvm-ranlib.exe")),
                strip   = _compiler(cmd_args(llvm, format = "{}/bin/llvm-strip.exe")),
                dwp        = None,
                bolt_msdk  = None,
            ),

            # ── C++ compiler (clang-cl) ──────────────────────────────────────
            cxx_compiler_info = CxxCompilerInfo(
                compiler           = _compiler(clang_cl),
                preprocessor_flags = sysroot_include_flags,
                compiler_flags     = ctx.attrs.cxx_flags,
                compiler_type      = "clang_cl",
                supports_two_phase_compilation = False,
                supports_content_based_paths   = False,
            ),

            # ── C compiler (clang-cl) ────────────────────────────────────────
            c_compiler_info = CCompilerInfo(
                compiler           = _compiler(clang_cl),
                preprocessor_flags = sysroot_include_flags,
                compiler_flags     = ctx.attrs.c_flags,
                compiler_type      = "clang_cl",
                supports_content_based_paths = False,
            ),

            # ── ASM compiler (.S files via clang-cl) ─────────────────────────
            as_compiler_info = CCompilerInfo(
                compiler      = _compiler(clang_cl),
                compiler_type = "clang_cl",
                supports_content_based_paths = False,
            ),

            # ── MASM-style ASM (ml64 equivalent — use clang-cl) ─────────────
            asm_compiler_info = CCompilerInfo(
                compiler      = _compiler(clang_cl),
                compiler_type = "clang_cl",
            ),

            # ── cvtres (not needed for clang-cl builds, stub it) ─────────────
            cvtres_compiler_info = CvtresCompilerInfo(
                compiler           = RunInfo(args = ["cvtres.exe"]),
                preprocessor_flags = [],
                compiler_flags     = [],
                compiler_type      = "clang_cl",
            ),

            # ── RC compiler (resource compiler — llvm-rc) ────────────────────
            rc_compiler_info = RcCompilerInfo(
                compiler           = _compiler(llvm_rc),
                preprocessor_flags = sysroot_include_flags,
                compiler_flags     = ctx.attrs.rc_flags,
                compiler_type      = "clang_cl",
            ),

            # ── Toolchain behaviour ──────────────────────────────────────────
            # clang-cl uses -H (show_headers) for dep tracking, not /showIncludes
            cpp_dep_tracking_mode       = DepTrackingMode("show_headers"),
            header_mode                 = HeaderMode("symlink_tree_only"),
            pic_behavior                = PicBehavior("not_supported"),  # Windows
            use_dep_files               = True,
            llvm_link                   = None,
            runtime_dependency_handling = RuntimeDependencyHandling("no_symlink"),
        ),
        CxxPlatformInfo(name = "windows-x86_64"),
    ]


hermetic_cxx_toolchain = rule(
    impl = _hermetic_cxx_toolchain_impl,
    attrs = {
        # ── Required inputs ──────────────────────────────────────────────────
        # Prebuilt LLVM distribution (from http_archive)
        "llvm_dist":    attrs.exec_dep(providers = [DefaultInfo]),
        # xwin-splatted MSVC sysroot (from genrule)
        "msvc_sysroot": attrs.exec_dep(providers = [DefaultInfo]),

        # ── Optional flag overrides ──────────────────────────────────────────
        "c_flags":         attrs.list(attrs.arg(), default = []),
        "cxx_flags":       attrs.list(attrs.arg(), default = []),
        "link_flags":      attrs.list(attrs.arg(), default = []),
        "post_link_flags": attrs.list(attrs.arg(), default = []),
        "rc_flags":        attrs.list(attrs.arg(), default = []),
        "link_style":    attrs.string(default = "static"),
        "link_ordering": attrs.option(attrs.enum(LinkOrdering.values()), default = None),

        # ── Internal prelude deps ────────────────────────────────────────────
        "_internal_tools": attrs.exec_dep(
            providers = [CxxInternalTools],
            default = "prelude//cxx/tools:internal_tools",
        ),
    },
    is_toolchain_rule = True,
)
