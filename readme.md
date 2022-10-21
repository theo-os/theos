# TheOS

[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-%23FE5196?logo=conventionalcommits&logoColor=white)](https://conventionalcommits.org)
[![Zig](https://img.shields.io/badge/Zig-%23F7A41D.svg?logo=zig&logoColor=white)](https://ziglang.org)

**A statically-linked linux distribution written with [zig](https://github.com/ziglang/zig).**

## Prerequisites

- [Latest zig master](https://ziglang.org/download)

## Development On Linux

> ⚠️  If you are not root, you will need to prefix the following command with sudo or doas.

```sh
zig build -Dtarget=native-linux-musl run-qemu
```

This will drop you into a chroot environment in the current directory, running `bin/tsh`.

