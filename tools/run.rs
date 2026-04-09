use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() -> Result<(), Box<dyn Error>> {
    let arch = env::var("ARCH").unwrap_or_else(|_| "x86_64".to_string());
    if arch != "x86_64" {
        return Err(format!("unsupported architecture: {arch}").into());
    }

    let root = env::current_dir()?;
    let ovmf_fd = required_env_path("BUCK_OVMF_FD")?;
    let kernel_bin = required_env_path("BUCK_KERNEL_BIN")?;
    let mkrootfs_bin = required_env_path("BUCK_MKROOTFS_BIN")?;
    let native_init_exe = required_env_path("BUCK_NATIVE_INIT_EXE")?;
    let child_exe = required_env_path("BUCK_CHILD_EXE")?;
    let ntdll_dll = required_env_path("BUCK_NTDLL_DLL")?;

    let rootfs_img = root.join("rootfs.img");
    let efi_root = root.join("efi_root");
    let efi_boot_file = "BOOTX64.EFI";
    let qemu_bin = "qemu-system-x86_64";

    let kernel_init = env::var("KERNEL_INIT").unwrap_or_default();
    let kernel_root = env::var("KERNEL_ROOT").unwrap_or_else(|_| "/dev/vda".to_string());
    let kernel_rootfstype = env::var("KERNEL_ROOTFSTYPE").unwrap_or_else(|_| "crabfs".to_string());
    let kernel_cmdline = env::var("KERNEL_CMDLINE").unwrap_or_default();
    let rootfs_size_mib = env::var("ROOTFS_SIZE_MIB").unwrap_or_default();
    let qemu_mem = env::var("QEMU_MEM").unwrap_or_else(|_| "512M".to_string());
    let empty_rootfs_dir = root.join(".empty-rootfs");

    if let Some(path) = env::var_os("KERNEL_RUSTFLAGS") {
        eprintln!("warning: KERNEL_RUSTFLAGS is ignored by the Buck2 build");
        drop(path);
    }

    remove_if_exists(&empty_rootfs_dir)?;
    fs::create_dir_all(empty_rootfs_dir.join("Windows/System32"))?;
    install_native_init_to_dir(&native_init_exe, &child_exe, &ntdll_dll, &empty_rootfs_dir)?;
    build_rootfs_from_dir(
        &mkrootfs_bin,
        &empty_rootfs_dir,
        &rootfs_img,
        rootfs_size_mib.as_str(),
    )?;

    remove_if_exists(&efi_root)?;
    fs::create_dir_all(efi_root.join("EFI/BOOT"))?;
    copy_file(
        &kernel_bin,
        &efi_root.join(format!("EFI/BOOT/{efi_boot_file}")),
    )?;

    if env::var_os("KERNEL_INIT").is_some()
        || env::var_os("KERNEL_ROOT").is_some()
        || env::var_os("KERNEL_ROOTFSTYPE").is_some()
        || env::var_os("KERNEL_CMDLINE").is_some()
    {
        eprintln!("warning: direct UEFI boot ignores kernel cmdline settings in the Buck runner");
    }

    let mut qemu_args = vec![
        "-bios".to_string(),
        ovmf_fd.display().to_string(),
        "-smp".to_string(),
        "2".to_string(),
        "-drive".to_string(),
        format!("file=fat:rw:{},format=raw", efi_root.display()),
        "-drive".to_string(),
        format!("if=none,id=drv0,file={},format=raw", rootfs_img.display()),
        "-device".to_string(),
        "virtio-blk-pci,drive=drv0".to_string(),
        "-serial".to_string(),
        "stdio".to_string(),
        "-display".to_string(),
        "none".to_string(),
        "-m".to_string(),
        qemu_mem,
    ];
    if cfg!(target_os = "linux") && Path::new("/dev/kvm").exists() {
        qemu_args.push("-accel".to_string());
        qemu_args.push("kvm".to_string());
    }

    run_interactive_cmd(Command::new(qemu_bin).args(qemu_args).current_dir(&root))?;
    Ok(())
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name).map(PathBuf::from)
}

fn required_env_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    env_path(name).ok_or_else(|| {
        format!("missing {name}; run this binary through buck2 so artifact paths are injected")
            .into()
    })
}

fn build_rootfs_from_dir(
    mkrootfs_bin: &Path,
    source: &Path,
    output: &Path,
    rootfs_size_mib: &str,
) -> Result<(), Box<dyn Error>> {
    let size_mib = if rootfs_size_mib.is_empty() {
        resolve_rootfs_size_mib(source)?
    } else {
        rootfs_size_mib.to_string()
    };

    run_cmd(
        Command::new(mkrootfs_bin)
            .arg("--source")
            .arg(source)
            .arg("--output")
            .arg(output)
            .arg("--size-mib")
            .arg(size_mib),
    )?;
    Ok(())
}

fn resolve_rootfs_size_mib(source: &Path) -> Result<String, Box<dyn Error>> {
    let output = run_cmd(Command::new("du").arg("-sm").arg(source))?;
    let used_mib: u64 = output
        .split_whitespace()
        .next()
        .ok_or("du returned no size")?
        .parse()?;
    let mut size_mib = used_mib + used_mib / 4 + 256;
    if size_mib < 64 {
        size_mib = 64;
    }
    Ok(size_mib.to_string())
}

fn run_import_rootfs(root: &Path, tarball: &Path, staging: &Path) -> Result<(), Box<dyn Error>> {
    run_cmd(
        Command::new(root.join("tools/import_rootfs.sh"))
            .arg(tarball)
            .arg(staging),
    )?;
    Ok(())
}

fn install_native_init_to_dir(
    native_init_exe: &Path,
    child_exe: &Path,
    ntdll_dll: &Path,
    target_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(target_dir.join("Windows/System32"))?;
    copy_file(
        native_init_exe,
        &target_dir.join("Windows/System32/init.exe"),
    )?;
    copy_file(child_exe, &target_dir.join("Windows/System32/child.exe"))?;
    copy_file(ntdll_dll, &target_dir.join("Windows/System32/ntdll.dll"))?;
    Ok(())
}

fn copy_file(from: &Path, to: &Path) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(from, to)?;
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn run_cmd(cmd: &mut Command) -> Result<String, Box<dyn Error>> {
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(format!(
            "command failed: {}\nstdout:\n{}\nstderr:\n{}",
            command_display(cmd),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn run_interactive_cmd(cmd: &mut Command) -> Result<(), Box<dyn Error>> {
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err(format!(
            "command failed with status {}: {}",
            status,
            command_display(cmd),
        )
        .into());
    }
    Ok(())
}

fn command_display(cmd: &Command) -> String {
    let program = cmd.get_program().to_string_lossy();
    let args = cmd
        .get_args()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {args}")
    }
}
