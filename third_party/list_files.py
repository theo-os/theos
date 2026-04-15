#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys


def should_skip(path: pathlib.Path) -> bool:
    parts = path.as_posix().lower()
    name = path.name.lower()
    if "/asm/" in parts:
        return True
    if any(
        token in parts
        for token in (
            "/aarch64",
            "/alpha",
            "/arm",
            "/hppa",
            "/ia64",
            "/loongarch",
            "/m68k",
            "/mips",
            "/ppc",
            "/powerpc",
            "/riscv",
            "/s390",
            "/sparc",
        )
    ):
        return True
    if any(
        token in name
        for token in (
            "aarch64",
            "alpha",
            "armv",
            "hppa",
            "ia64",
            "loongarch",
            "m68k",
            "mips",
            "ppc",
            "powerpc",
            "riscv",
            "s390",
            "sparc",
        )
    ):
        return True
    if "/lpdir" in parts:
        return True
    if "/async/arch/async_posix.c" in parts:
        return True
    if name in {"c_brotli.c", "c_zlib.c", "c_zstd.c"}:
        return True
    if "acvp" in name:
        return True
    if name.startswith("poly1305_"):
        return True
    if "ktls" in name:
        return True
    if "/providers/fips/" in parts:
        return True
    if parts.endswith("/providers/common/securitycheck_fips.c"):
        return True
    if name == "ssl_cert_comp.c":
        return True
    if name.startswith("ecp_nistz256"):
        return True
    if "/threads_pthread.c" in parts:
        return True
    if "/dso/dso_dl.c" in parts:
        return True
    if "/dso/dso_dlfcn.c" in parts:
        return True
    if "/dso/dso_vms.c" in parts:
        return True
    if "/dso/dso_openssl.c" in parts:
        return True
    if parts.endswith("cap.c"):
        return True
    if parts.endswith("x86_64-gcc.c"):
        return True
    if parts.endswith("uplink.c"):
        return True
    if "uplink-" in parts:
        return True
    return False


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: list_files.py <base_dir> <root1> [<root2> ...]", file=sys.stderr)
        return 1

    base_dir = pathlib.Path(sys.argv[1]).resolve()
    roots = [pathlib.Path(arg).resolve() for arg in sys.argv[2:]]
    files: list[str] = []

    for root in roots:
        if root.is_dir():
            for source in sorted(root.rglob("*.c")):
                if should_skip(source):
                    continue
                files.append(source.relative_to(base_dir).as_posix())
        elif root.is_file() and root.suffix == ".c":
            if not should_skip(root):
                files.append(root.relative_to(base_dir).as_posix())

    for file_name in sorted(dict.fromkeys(files)):
        print(file_name)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
