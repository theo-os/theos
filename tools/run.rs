use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::UNIX_EPOCH;

const DEFAULT_WINDOWS_ISO: &str = "Win11_25H2_English_x64_v2.iso";
const WINDOWS_ROOTFS_MANIFEST: &str = "tools/windows-rootfs.txt";
const WINDOWS_ROOTFS_REAL_MANIFEST: &str = "tools/windows-rootfs-real.txt";

fn main() -> Result<(), Box<dyn Error>> {
    let arch = env::var("ARCH").unwrap_or_else(|_| "x86_64".to_string());
    if arch != "x86_64" {
        return Err(format!("unsupported architecture: {arch}").into());
    }

    let root = env::current_dir()?;
    let ovmf_fd = required_env_path("BAZEL_OVMF_FD")?;
    let kernel_bin = required_env_path("BAZEL_KERNEL_BIN")?;
    let mkrootfs_bin = required_env_path("BAZEL_MKROOTFS_BIN")?;
    let wimunpack_bin = required_env_path("BAZEL_WIMUNPACK_BIN")?;
    let native_init_dir = required_env_path("BAZEL_NATIVE_INIT_DIR")?;
    let native_init_exe = native_init_dir.join("init.exe");
    let child_exe = native_init_dir.join("child.exe");
    let ntdll_dll = native_init_dir.join("ntdll.dll");

    let rootfs_img = root.join("rootfs.img");
    let efi_root = root.join("efi_root");
    let efi_boot_file = "BOOTX64.EFI";
    let qemu_bin = "qemu-system-x86_64";

    let kernel_init = env::var("KERNEL_INIT").unwrap_or_default();
    let kernel_root = env::var("KERNEL_ROOT").unwrap_or_else(|_| "/dev/vda".to_string());
    let kernel_rootfstype = env::var("KERNEL_ROOTFSTYPE").unwrap_or_else(|_| "crabfs".to_string());
    let kernel_cmdline = env::var("KERNEL_CMDLINE").unwrap_or_default();
    let rootfs_size_mib = env::var("ROOTFS_SIZE_MIB").unwrap_or_default();
    let rootfs_profile = env::var("ROOTFS_PROFILE").unwrap_or_else(|_| "auto".to_string());
    let qemu_mem = env::var("QEMU_MEM").unwrap_or_else(|_| "512M".to_string());
    let rootfs_staging_dir = root.join(".rootfs-staging");
    let rootfs_extract_manifest = root.join(".rootfs-extract.manifest");
    let rootfs_build_manifest = root.join(".rootfs-build.manifest");
    let windows_rootfs_manifest = root.join(WINDOWS_ROOTFS_MANIFEST);
    let windows_rootfs_real_manifest = root.join(WINDOWS_ROOTFS_REAL_MANIFEST);
    let rootfs_iso = env::var_os("ROOTFS_ISO")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(DEFAULT_WINDOWS_ISO));
    let effective_profile = resolve_rootfs_profile(rootfs_profile.as_str(), &rootfs_iso)?;
    let rootfs_manifest = rootfs_manifest_for_profile(
        effective_profile,
        &windows_rootfs_manifest,
        &windows_rootfs_real_manifest,
    );

    if let Some(path) = env::var_os("KERNEL_RUSTFLAGS") {
        eprintln!("warning: KERNEL_RUSTFLAGS is ignored by the Bazel build");
        drop(path);
    }

    let build_signature = rootfs_build_signature(
        effective_profile,
        &rootfs_iso,
        rootfs_manifest,
        rootfs_size_mib.as_str(),
        &mkrootfs_bin,
        &native_init_exe,
        &child_exe,
        &ntdll_dll,
    )?;
    if rootfs_img.exists() && manifest_matches(&rootfs_build_manifest, &build_signature)? {
        eprintln!("info: reusing cached rootfs image {}", rootfs_img.display());
    } else {
        prepare_rootfs_staging(
            effective_profile,
            &wimunpack_bin,
            &rootfs_iso,
            rootfs_manifest,
            &rootfs_staging_dir,
            &rootfs_extract_manifest,
        )?;
        match effective_profile {
            RootfsProfile::Windows => {
                install_native_init_to_dir(
                    &native_init_exe,
                    &child_exe,
                    &ntdll_dll,
                    &rootfs_staging_dir,
                )?;
            }
            RootfsProfile::WindowsReal => {
                install_windows_real_init_to_dir(&rootfs_staging_dir)?;
            }
        }
        build_rootfs_from_dir(
            &mkrootfs_bin,
            &rootfs_staging_dir,
            &rootfs_img,
            rootfs_size_mib.as_str(),
        )?;
        write_manifest(&rootfs_build_manifest, &build_signature)?;
    }

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
        eprintln!("warning: direct UEFI boot ignores kernel cmdline settings in the Bazel runner");
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
        "mon:stdio".to_string(),
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
        format!("missing {name}; run this binary through bazel so artifact paths are injected")
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootfsProfile {
    Windows,
    WindowsReal,
}

fn resolve_rootfs_profile(profile: &str, iso_path: &Path) -> Result<RootfsProfile, Box<dyn Error>> {
    match profile {
        "windows" => {
            if iso_path.exists() {
                Ok(RootfsProfile::Windows)
            } else {
                Err(format!(
                    "ROOTFS_PROFILE=windows requested but ISO not found at {}",
                    iso_path.display()
                )
                .into())
            }
        }
        "windows-real" | "auto" => {
            if iso_path.exists() {
                Ok(RootfsProfile::WindowsReal)
            } else {
                Err(format!(
                    "ISO not found at {}; a real Windows ISO is required to build the rootfs",
                    iso_path.display()
                )
                .into())
            }
        }
        other => Err(format!(
            "unsupported ROOTFS_PROFILE={other}; expected auto, windows, or windows-real (minimal is no longer supported)"
        )
        .into()),
    }
}

fn rootfs_manifest_for_profile<'a>(
    profile: RootfsProfile,
    windows_manifest: &'a Path,
    windows_real_manifest: &'a Path,
) -> Option<&'a Path> {
    match profile {
        RootfsProfile::Windows => Some(windows_manifest),
        RootfsProfile::WindowsReal => Some(windows_real_manifest),
    }
}

fn prepare_rootfs_staging(
    profile: RootfsProfile,
    wimunpack_bin: &Path,
    iso_path: &Path,
    windows_rootfs_manifest: Option<&Path>,
    staging: &Path,
    extract_manifest: &Path,
) -> Result<(), Box<dyn Error>> {
    let Some(windows_rootfs_manifest) = windows_rootfs_manifest else {
        return Err("windows profile requires include-list manifest".into());
    };
    let expected_paths = read_include_manifest_paths(windows_rootfs_manifest)?;
    let extract_signature =
        rootfs_extract_signature(profile, iso_path, windows_rootfs_manifest, wimunpack_bin)?;
    if staging.exists()
        && manifest_matches(extract_manifest, &extract_signature)?
        && staging_contains_paths(staging, &expected_paths)
    {
        eprintln!("info: reusing cached Windows rootfs extraction");
    } else {
        remove_if_exists(staging)?;
        eprintln!("info: extracting rootfs from {}", iso_path.display());
        run_cmd(
            Command::new(wimunpack_bin)
                .arg("--iso")
                .arg(iso_path)
                .arg("--include-list")
                .arg(windows_rootfs_manifest)
                .arg("--output")
                .arg(staging),
        )?;
        write_manifest(extract_manifest, &extract_signature)?;
    }
    Ok(())
}

fn rootfs_extract_signature(
    profile: RootfsProfile,
    iso_path: &Path,
    windows_rootfs_manifest: &Path,
    wimunpack_bin: &Path,
) -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "profile={}\niso={}\ninclude_list={}\nwimunpack={}\n",
        match profile {
            RootfsProfile::Windows => "windows",
            RootfsProfile::WindowsReal => "windows-real",
        },
        file_signature(iso_path)?,
        file_signature(windows_rootfs_manifest)?,
        file_signature(wimunpack_bin)?,
    ))
}

fn rootfs_build_signature(
    profile: RootfsProfile,
    iso_path: &Path,
    windows_rootfs_manifest: Option<&Path>,
    rootfs_size_mib: &str,
    mkrootfs_bin: &Path,
    native_init_exe: &Path,
    child_exe: &Path,
    ntdll_dll: &Path,
) -> Result<String, Box<dyn Error>> {
    let mut signature = String::new();
    signature.push_str(match profile {
        RootfsProfile::Windows => "profile=windows\n",
        RootfsProfile::WindowsReal => "profile=windows-real\n",
    });
    if let Some(manifest) = windows_rootfs_manifest {
        signature.push_str(&format!("iso={}\n", file_signature(iso_path)?));
        signature.push_str(&format!("include_list={}\n", file_signature(manifest)?));
    }
    signature.push_str(&format!("rootfs_size_mib={rootfs_size_mib}\n"));
    signature.push_str(&format!("mkrootfs={}\n", file_signature(mkrootfs_bin)?));
    match profile {
        RootfsProfile::Windows => {
            signature.push_str(&format!("init={}\n", file_signature(native_init_exe)?));
            signature.push_str(&format!("child={}\n", file_signature(child_exe)?));
            signature.push_str(&format!("ntdll={}\n", file_signature(ntdll_dll)?));
        }
        RootfsProfile::WindowsReal => {
            signature.push_str("overlay=windows-real\n");
        }
    }
    Ok(signature)
}

fn read_include_manifest_paths(manifest: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut paths = Vec::new();
    let contents = fs::read_to_string(manifest)?;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        paths.push(PathBuf::from(trimmed.replace('\\', "/")));
    }
    Ok(paths)
}

fn staging_contains_paths(staging: &Path, expected_paths: &[PathBuf]) -> bool {
    expected_paths.iter().all(|rel| staging.join(rel).exists())
}

fn file_signature(path: &Path) -> Result<String, Box<dyn Error>> {
    let metadata = fs::metadata(path)?;
    let modified = metadata.modified()?.duration_since(UNIX_EPOCH)?;
    Ok(format!(
        "{}:{}:{}:{}",
        path.display(),
        metadata.len(),
        modified.as_secs(),
        modified.subsec_nanos()
    ))
}

fn manifest_matches(path: &Path, expected: &str) -> Result<bool, Box<dyn Error>> {
    match fs::read_to_string(path) {
        Ok(existing) => Ok(existing == expected),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn write_manifest(path: &Path, contents: &str) -> Result<(), Box<dyn Error>> {
    fs::write(path, contents)?;
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

fn install_windows_real_init_to_dir(target_dir: &Path) -> Result<(), Box<dyn Error>> {
    let system32 = target_dir.join("Windows/System32");
    let autochk = system32.join("autochk.exe");
    if !autochk.exists() {
        return Err(format!(
            "ROOTFS_PROFILE=windows-real requires {} in staged rootfs",
            autochk.display()
        )
        .into());
    }
    copy_file(&autochk, &system32.join("init.exe"))?;
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
