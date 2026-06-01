use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return Ok(());
    }

    let project_root = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("no parent directory")?
        .to_path_buf();
    env::set_current_dir(&project_root)?;

    match args[1].as_str() {
        "build" => build_host(&project_root)?,
        "build-kernel" => build_kernel(&project_root)?,
        "build-native" => build_native_init(&project_root)?,
        "build-all" => {
            build_kernel(&project_root)?;
            build_native_init(&project_root)?;
            build_host(&project_root)?;
        }
        "lint" | "clippy" => {
            run_cmd(
                Command::new("cargo")
                    .args([
                        "clippy",
                        "--workspace",
                        "--exclude",
                        "xtask",
                        "--exclude",
                        "kernel",
                    ])
                    .current_dir(&project_root),
            )?;
            run_cmd(
                Command::new("cargo")
                    .args(["clippy", "-p", "kernel"])
                    .current_dir(&project_root),
            )?;
        }
        "run" => {
            build_kernel(&project_root)?;
            build_native_init(&project_root)?;
            build_host(&project_root)?;
            run_qemu(&project_root)?;
        }
        "help" | "--help" | "-h" => print_help(),
        other => {
            return Err(format!("unknown command: {other}").into());
        }
    }
    Ok(())
}

fn print_help() {
    eprintln!("usage: cargo xtask <command>");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  build          build host tools and libraries");
    eprintln!("  build-kernel   build the kernel (x86_64-unknown-uefi)");
    eprintln!("  build-native   build userspace native_init (C/asm)");
    eprintln!("  build-all      build everything");
    eprintln!("  lint/clippy    run clippy on all crates");
    eprintln!("  run            build everything and run in QEMU");
    eprintln!();
    eprintln!("Kernel builds require the x86_64-unknown-uefi target:");
    eprintln!("  rustup target add x86_64-unknown-uefi");
}

/// Build all host-targeted workspace crates (tools and libraries).
fn build_host(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("==> building host crates (tools & libraries)");
    run_cmd(
        Command::new("cargo")
            .args([
                "build",
                "--workspace",
                "--exclude",
                "xtask",
                "--exclude",
                "kernel",
            ])
            .current_dir(root),
    )?;
    Ok(())
}

/// Build the kernel for x86_64-unknown-uefi.
fn build_kernel(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("==> building kernel (x86_64-unknown-uefi)");

    // Ensure the UEFI target is installed
    let target_check = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()?;
    let installed = String::from_utf8_lossy(&target_check.stdout);
    if !installed.contains("x86_64-unknown-uefi") {
        eprintln!("note: installing x86_64-unknown-uefi target...");
        run_cmd(Command::new("rustup").args(["target", "add", "x86_64-unknown-uefi"]))?;
    }

    run_cmd(
        Command::new("cargo")
            .args([
                "+nightly",
                "build",
                "-p",
                "kernel",
                "--target",
                "x86_64-unknown-uefi",
                "-Z",
                "build-std=core,alloc",
            ])
            .current_dir(root),
    )?;
    Ok(())
}

/// Build the native_init userspace (C + asm files, compiled with clang/lld-link).
fn build_native_init(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("==> building native_init (C -> PE/COFF)");
    let native_dir = root.join("userspace/native_init");
    let out_dir = root.join("target/xtask/native_init");

    std::fs::create_dir_all(&out_dir)?;
    let out = |name: &str| out_dir.join(name);

    let cflags = [
        "--target=x86_64-pc-windows-msvc",
        "-ffreestanding",
        "-fno-stack-protector",
        "-fno-builtin",
        "-c",
    ];
    let asm_flags = ["--target=x86_64-pc-windows-msvc", "-c"];

    let obj = |name: &str| out_dir.join(name.replace(".c", ".obj").replace(".S", ".obj"));
    let src = |name: &str| native_dir.join(name);

    for (file, flags) in &[
        ("init.c", &cflags[..]),
        ("child.c", &cflags[..]),
        ("init_reloc.c", &cflags[..]),
        ("ntdll_reloc.c", &cflags[..]),
        ("syscall_stubs.S", &asm_flags[..]),
        ("ntdll_stubs.S", &asm_flags[..]),
    ] {
        run_cmd(
            Command::new("clang")
                .args(*flags)
                .arg("-o")
                .arg(obj(file))
                .arg(src(file))
                .current_dir(root),
        )?;
    }

    // Link ntdll.dll
    run_cmd(
        Command::new("lld-link")
            .args([
                "/dll",
                "/noentry",
                "/nodefaultlib",
                "/machine:x64",
                "/base:0x140000000",
                &format!("/def:{}", src("ntdll.def").display()),
                &format!("/out:{}", out("ntdll.dll").display()),
                &format!("/implib:{}", out("ntdll.lib").display()),
                &obj("ntdll_stubs.obj").display().to_string(),
                &obj("ntdll_reloc.obj").display().to_string(),
            ])
            .current_dir(root),
    )?;

    // Link init.exe
    run_cmd(
        Command::new("lld-link")
            .args([
                "/entry:start",
                "/subsystem:native",
                "/nodefaultlib",
                "/machine:x64",
                "/fixed:no",
                &format!("/out:{}", out("init.exe").display()),
                &obj("init.obj").display().to_string(),
                &obj("init_reloc.obj").display().to_string(),
                &out("ntdll.lib").display().to_string(),
            ])
            .current_dir(root),
    )?;

    // Link child.exe
    run_cmd(
        Command::new("lld-link")
            .args([
                "/entry:start",
                "/subsystem:native",
                "/nodefaultlib",
                "/machine:x64",
                "/fixed:no",
                &format!("/out:{}", out("child.exe").display()),
                &obj("child.obj").display().to_string(),
                &obj("init_reloc.obj").display().to_string(),
                &out("ntdll.lib").display().to_string(),
            ])
            .current_dir(root),
    )?;

    eprintln!("    native_init outputs in {}", out_dir.display());
    Ok(())
}

/// Run the kernel in QEMU.
fn run_qemu(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("==> launching QEMU");

    let profile = env::var("CARGO_PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_dir = root.join("target");
    let uefi_target_dir = target_dir.join("x86_64-unknown-uefi").join(&profile);

    let kernel_bin = uefi_target_dir.join("kernel.efi");
    let mkrootfs_bin = target_dir.join(&profile).join("mkrootfs");
    let wimunpack_bin = target_dir.join(&profile).join("wimunpack");
    let fetch_rootfs_bin = target_dir.join(&profile).join("fetch-rootfs");
    let run_bin = target_dir.join(&profile).join("run");
    let native_init_dir = target_dir.join("xtask/native_init");
    let ovmf_fd = locate_or_download_ovmf(root)?;

    let mut cmd = Command::new(&run_bin);
    cmd.env("BUCK_OVMF_FD", &ovmf_fd)
        .env("BUCK_KERNEL_BIN", &kernel_bin)
        .env("BUCK_MKROOTFS_BIN", &mkrootfs_bin)
        .env("BUCK_WIMUNPACK_BIN", &wimunpack_bin)
        .env("BUCK_FETCH_ROOTFS_BIN", &fetch_rootfs_bin)
        .env("BUCK_NATIVE_INIT_EXE", native_init_dir.join("init.exe"))
        .env("BUCK_CHILD_EXE", native_init_dir.join("child.exe"))
        .env("BUCK_NTDLL_DLL", native_init_dir.join("ntdll.dll"));

    for var in &[
        "KERNEL_INIT",
        "KERNEL_ROOT",
        "KERNEL_ROOTFSTYPE",
        "KERNEL_CMDLINE",
        "ROOTFS_SIZE_MIB",
        "ROOTFS_PROFILE",
        "QEMU_MEM",
        "ROOTFS_ISO",
        "ARCH",
    ] {
        if let Ok(val) = env::var(var) {
            cmd.env(var, val);
        }
    }

    cmd.current_dir(root);
    run_interactive_cmd(cmd)?;
    Ok(())
}

fn locate_or_download_ovmf(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let cached = root.join("target/xtask/OVMF.fd");
    if cached.exists() {
        return Ok(cached);
    }
    for path in &[
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/edk2/x64/OVMF.fd",
        "/usr/share/edk2-ovmf/x64/OVMF.fd",
        "/usr/share/qemu/ovmf-x86_64.bin",
    ] {
        let p = Path::new(path);
        if p.exists() {
            std::fs::create_dir_all(cached.parent().unwrap())?;
            std::fs::copy(p, &cached)?;
            return Ok(cached);
        }
    }
    eprintln!("note: downloading OVMF firmware...");
    let url = "https://github.com/retrage/edk2-nightly/raw/8b82cef2060fb27e07011d32911616084c8742ed/bin/DEBUGX64_OVMF.fd";
    std::fs::create_dir_all(cached.parent().unwrap())?;
    let status = Command::new("curl")
        .args(["-Lo", &cached.display().to_string(), url])
        .status()?;
    if !status.success() {
        return Err("failed to download OVMF firmware".into());
    }
    Ok(cached)
}

fn run_cmd(cmd: &mut Command) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("    running: {}", display_cmd(cmd));
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!(
            "command failed with status {}: {}",
            status,
            display_cmd(cmd)
        )
        .into());
    }
    Ok(())
}

fn run_interactive_cmd(mut cmd: Command) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("    running: {}", display_cmd(&cmd));
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err(format!(
            "command failed with status {}: {}",
            status,
            display_cmd(&cmd),
        )
        .into());
    }
    Ok(())
}

fn display_cmd(cmd: &Command) -> String {
    let program = cmd.get_program().to_string_lossy();
    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into()).collect();
    if args.is_empty() {
        program.into_owned()
    } else {
        format!("{program} {}", args.join(" "))
    }
}
