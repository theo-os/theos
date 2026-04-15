rust_binary(
    name = "run_impl",
    srcs = ["tools/run.rs"],
    crate_root = "tools/run.rs",
    edition = "2024",
    deps = [
        "third-party//:clap",
        "third-party//:futures-util",
        "third-party//:reqwest",
        "third-party//:tokio",
        "third-party//:rustls-graviola",
    ],
    visibility = ["PUBLIC"],
)

rust_binary(
    name = "uup_fetch_impl",
    srcs = ["tools/uup_fetch.rs"],
    crate_root = "tools/uup_fetch.rs",
    edition = "2024",
    deps = [
        "third-party//:base64",
        "third-party//:clap",
        "third-party//:flate2",
        "third-party//:futures-util",
        "third-party//:indicatif",
        "third-party//:reqwest",
        "third-party//:tokio",
        "third-party//:rustls-graviola",
        "//lib/wim_lzx:wim_lzx",

    ],
    visibility = ["PUBLIC"],
)

http_file(
    name = "ovmf_firmware",
    urls = ["https://github.com/retrage/edk2-nightly/raw/8b82cef2060fb27e07011d32911616084c8742ed/bin/DEBUGX64_OVMF.fd"],
    sha256 = "727056000a2b1e6adfa36662fb570a27912ff961dbd7aedb8ad59b724567867a",
)

command_alias(
    name = "run",
    exe = ":run_impl",
    env = {
        "RUN_IMPL": "$(location :run_impl)",
        "BUCK_OVMF_FD": "$(location :ovmf_firmware)",
        "BUCK_KERNEL_BIN": "$(location //kernel:kernel_artifact)",
        "BUCK_MKROOTFS_BIN": "$(location //tools/mkrootfs:mkrootfs)",
        "BUCK_WIMUNPACK_BIN": "$(location //tools/wimunpack:wimunpack)",
        "BUCK_UUP_FETCH_BIN": "$(location :uup_fetch_impl)",
    },
    visibility = ["PUBLIC"],
)
