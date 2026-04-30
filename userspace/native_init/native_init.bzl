def _native_init_impl(ctx):
    out_dir = ctx.actions.declare_directory(ctx.label.name)

    command = """
set -euo pipefail
out_dir="$1"
init_c="$2"
child_c="$3"
init_reloc_c="$4"
ntdll_def="$5"
ntdll_reloc_c="$6"
syscall_stubs_s="$7"
ntdll_stubs_s="$8"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

clang --target=x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -fno-builtin \
    -c "$init_c" -o "$tmpdir/init.obj"
clang --target=x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -fno-builtin \
    -c "$child_c" -o "$tmpdir/child.obj"
clang --target=x86_64-pc-windows-msvc -c "$syscall_stubs_s" -o "$tmpdir/syscall_stubs.obj"
clang --target=x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -fno-builtin \
    -c "$init_reloc_c" -o "$tmpdir/init_reloc.obj"
clang --target=x86_64-pc-windows-msvc -c "$ntdll_stubs_s" -o "$tmpdir/ntdll_stubs.obj"
clang --target=x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -fno-builtin \
    -c "$ntdll_reloc_c" -o "$tmpdir/ntdll_reloc.obj"

mkdir -p "$out_dir"
lld-link /dll /noentry /nodefaultlib /machine:x64 \
    /base:0x140000000 /def:"$ntdll_def" /out:"$out_dir/ntdll.dll" /implib:"$out_dir/ntdll.lib" \
    "$tmpdir/ntdll_stubs.obj" "$tmpdir/ntdll_reloc.obj"
lld-link /entry:start /subsystem:native /nodefaultlib /machine:x64 /fixed:no \
    /out:"$out_dir/init.exe" "$tmpdir/init.obj" "$tmpdir/init_reloc.obj" "$out_dir/ntdll.lib"
lld-link /entry:start /subsystem:native /nodefaultlib /machine:x64 /fixed:no \
    /out:"$out_dir/child.exe" "$tmpdir/child.obj" "$tmpdir/init_reloc.obj" "$out_dir/ntdll.lib"
"""

    ctx.actions.run_shell(
        inputs = [
            ctx.file.init_c,
            ctx.file.child_c,
            ctx.file.init_reloc_c,
            ctx.file.ntdll_def,
            ctx.file.ntdll_reloc_c,
            ctx.file.syscall_stubs_s,
            ctx.file.ntdll_stubs_s,
        ],
        outputs = [out_dir],
        arguments = [
            out_dir.path,
            ctx.file.init_c.path,
            ctx.file.child_c.path,
            ctx.file.init_reloc_c.path,
            ctx.file.ntdll_def.path,
            ctx.file.ntdll_reloc_c.path,
            ctx.file.syscall_stubs_s.path,
            ctx.file.ntdll_stubs_s.path,
        ],
        command = command,
        mnemonic = "NativeInit",
        progress_message = "Building native Windows init bundle",
    )

    return [DefaultInfo(files = depset([out_dir]))]

native_init = rule(
    implementation = _native_init_impl,
    attrs = {
        "init_c": attr.label(allow_single_file = True, mandatory = True),
        "child_c": attr.label(allow_single_file = True, mandatory = True),
        "init_reloc_c": attr.label(allow_single_file = True, mandatory = True),
        "ntdll_def": attr.label(allow_single_file = True, mandatory = True),
        "ntdll_reloc_c": attr.label(allow_single_file = True, mandatory = True),
        "syscall_stubs_s": attr.label(allow_single_file = True, mandatory = True),
        "ntdll_stubs_s": attr.label(allow_single_file = True, mandatory = True),
    },
)
