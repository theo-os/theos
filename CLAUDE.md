# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

Theos is a Windows NT-compatible kernel written in Rust (2024 edition) targeting x86_64. It implements NT system calls to run Windows PE executables, with support for UEFI EFI stub booting.

## Build system

The project uses **Buck2** (not Cargo) with reindeer for dependency management. Standard `cargo build` will not work.

```bash
# Build everything
buck2 build //...

# Run in QEMU
buck2 run //:run

# Run with custom options
QEMU_MEM=1G ROOTFS_PROFILE=auto buck2 run //:run
```

Key runtime env vars: `KERNEL_INIT`, `KERNEL_ROOT`, `KERNEL_ROOTFSTYPE`, `KERNEL_CMDLINE`, `ROOTFS_SIZE_MIB`, `ROOTFS_PROFILE` (auto/lite/real), `QEMU_MEM` (default 512M), `ROOTFS_ISO`, `ARCH`.

## Linting / formatting

There is currently no linting workflow.

## Testing

There is no formal test suite. Testing is done by running the kernel in QEMU via `buck2 run //:run` and observing behavior. CI only runs `buck2 build //...`.

## Architecture

### Kernel (`kernel/`)

- **`kernel.rs`** — entry point; handles both UEFI and Limine boot paths
- **`user.rs`** — user-mode execution context, memory space management, PE loading (~120KB, central to NT compat)
- **`syscall.rs`** — x86_64 SYSCALL/SYSRET handler setup
- **`process.rs`** — task/process structures and scheduler (priority classes: Game/Normal/Background, credit-based wake)
- **`nt.rs`** — NT status codes, handle types, access masks, memory flags
- **`vfs.rs`** — virtual filesystem layer (pipes, CrabFS, special files)
- **`paging.rs`**, **`allocator.rs`** — page tables and linked-list heap
- **`apic.rs`**, **`gdt.rs`**, **`idt.rs`**, **`smp.rs`** — CPU/interrupt infrastructure
- **`virtio_blk.rs`**, **`pci.rs`** — VirtIO block device and PCI enumeration

### Libraries (`lib/`)

- **`crabfs`** — custom XFS-like filesystem (used as the rootfs format), works in `no_std`
- **`regf`** — Windows registry hive parser (reads .SAM/.SYSTEM/.SOFTWARE hives)
- **`loader`** — PE/ELF loader using goblin
- **`iso9660`**, **`udf`** — disc filesystem readers
- **`wim_lzx`** — WIM image and LZX decompression

### Tools (`tools/`)

- **`run.rs`** — QEMU launcher: extracts Windows rootfs from ISO via wimunpack, creates CrabFS images, launches QEMU
- **`mkrootfs`** — creates CrabFS filesystem images from directories
- **`wimunpack`** — extracts Windows WIM images from ISO files

### Userspace (`userspace/native_init/`)

Minimal Windows userspace compiled with clang targeting `x86_64-pc-windows-msvc`:
- `init.exe` — init process (Windows PE)
- `child.exe` — child process example
- `ntdll.dll` — minimal NTDLL stub with syscall stubs

## Key conventions

- All kernel code is `#![no_std]`; library crates use `std` feature gates where needed
- Rust 2024 edition throughout (requires nightly)
- Buck2 workspace cells: root, prelude, toolchains, third-party — dependency changes go through reindeer
- The repo uses Jujutsu (`jj`) alongside git; the development branch is `canon`
