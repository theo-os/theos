use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::UNIX_EPOCH;

const DEFAULT_WINDOWS_ISO: &str = "Win11_25H2_English_x64_v2.iso";
const WINDOWS_ROOTFS_MANIFEST: &str = "tools/windows-rootfs.txt";
const WINDOWS_ROOTFS_REAL_MANIFEST: &str = "tools/windows-rootfs-real.txt";

#[derive(Clone, Debug)]
enum WindowsSource {
    Iso(PathBuf),
    Wim(PathBuf),
}

#[derive(Clone, Debug)]
struct UupConfig {
    output_dir: PathBuf,
    update_id: Option<String>,
    revision: Option<String>,
    build: String,
    arch: String,
    ring: String,
    flight: String,
    sku: String,
    release_type: String,
    branch: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    rustls_graviola::default_provider()
        .install_default()
        .unwrap();
    let arch = env::var("ARCH").unwrap_or_else(|_| "x86_64".to_string());
    if arch != "x86_64" {
        return Err(format!("unsupported architecture: {arch}").into());
    }

    let root = env::current_dir()?;
    let ovmf_fd = required_env_path("BUCK_OVMF_FD")?;
    let kernel_bin = required_env_path("BUCK_KERNEL_BIN")?;
    let mkrootfs_bin = required_env_path("BUCK_MKROOTFS_BIN")?;
    let wimunpack_bin = required_env_path("BUCK_WIMUNPACK_BIN")?;
    let uup_fetch_bin = required_env_path("BUCK_UUP_FETCH_BIN")?;

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
    let rootfs_staging_dir = root.join(".rootfs-staging");
    let rootfs_extract_manifest = root.join(".rootfs-extract.manifest");
    let rootfs_build_manifest = root.join(".rootfs-build.manifest");
    let windows_rootfs_manifest = root.join(WINDOWS_ROOTFS_MANIFEST);
    let windows_rootfs_real_manifest = root.join(WINDOWS_ROOTFS_REAL_MANIFEST);
    let rootfs_iso = env::var_os("ROOTFS_ISO")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(DEFAULT_WINDOWS_ISO));
    let uup_config = UupConfig {
        output_dir: root.join(".uup-cache"),
        update_id: env::var("ROOTFS_UUP_UPDATE_ID").ok(),
        revision: env::var("ROOTFS_UUP_REVISION").ok(),
        build: env::var("ROOTFS_UUP_BUILD").unwrap_or_else(|_| "29565.1000".to_string()),
        arch: env::var("ROOTFS_UUP_ARCH").unwrap_or_else(|_| "amd64".to_string()),
        ring: env::var("ROOTFS_UUP_RING").unwrap_or_else(|_| "WIF".to_string()),
        flight: env::var("ROOTFS_UUP_FLIGHT").unwrap_or_else(|_| "Active".to_string()),
        sku: env::var("ROOTFS_UUP_SKU").unwrap_or_else(|_| "48".to_string()),
        release_type: env::var("ROOTFS_UUP_TYPE").unwrap_or_else(|_| "Production".to_string()),
        branch: env::var("ROOTFS_UUP_BRANCH").unwrap_or_else(|_| "auto".to_string()),
    };
    let windows_source = resolve_windows_source(&root, &rootfs_iso, &uup_fetch_bin, &uup_config)?;
    let rootfs_manifest = Some(windows_rootfs_real_manifest.as_path());

    if let Some(path) = env::var_os("KERNEL_RUSTFLAGS") {
        eprintln!("warning: KERNEL_RUSTFLAGS is ignored by the Buck2 build");
        drop(path);
    }

    let build_signature = rootfs_build_signature(
        windows_source.as_ref(),
        rootfs_manifest,
        rootfs_size_mib.as_str(),
        &mkrootfs_bin,
    )?;
    if rootfs_img.exists() && manifest_matches(&rootfs_build_manifest, &build_signature)? {
        eprintln!("info: reusing cached rootfs image {}", rootfs_img.display());
    } else {
        prepare_rootfs_staging(
            &wimunpack_bin,
            windows_source.as_ref(),
            rootfs_manifest,
            &rootfs_staging_dir,
            &rootfs_extract_manifest,
        )?;
        install_windows_real_init_to_dir(&rootfs_staging_dir)?;
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

fn resolve_windows_source(
    root: &Path,
    iso_path: &Path,
    uup_fetch_bin: &Path,
    uup_config: &UupConfig,
) -> Result<Option<WindowsSource>, Box<dyn Error>> {
    if iso_path.exists() {
        Ok(Some(WindowsSource::Iso(iso_path.to_path_buf())))
    } else {
        let wim = fetch_uup_wim(root, uup_fetch_bin, uup_config)?;
        Ok(Some(WindowsSource::Wim(wim)))
    }
}

fn prepare_rootfs_staging(
    wimunpack_bin: &Path,
    windows_source: Option<&WindowsSource>,
    windows_rootfs_manifest: Option<&Path>,
    staging: &Path,
    extract_manifest: &Path,
) -> Result<(), Box<dyn Error>> {
    let Some(windows_rootfs_manifest) = windows_rootfs_manifest else {
        return Err("windows rootfs requires include-list manifest".into());
    };
    let Some(windows_source) = windows_source else {
        return Err("windows rootfs requires a Windows source (ISO or UUP WIM)".into());
    };

    let expected_paths = read_include_manifest_paths(windows_rootfs_manifest)?;
    let extract_signature =
        rootfs_extract_signature(windows_source, windows_rootfs_manifest, wimunpack_bin)?;
    if staging.exists()
        && manifest_matches(extract_manifest, &extract_signature)?
        && staging_contains_paths(staging, &expected_paths)
    {
        eprintln!("info: reusing cached Windows rootfs extraction");
    } else {
        remove_if_exists(staging)?;
        match windows_source {
            WindowsSource::Iso(iso_path) => {
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
            }
            WindowsSource::Wim(wim_path) => {
                eprintln!("info: extracting rootfs from {}", wim_path.display());
                run_cmd(
                    Command::new(wimunpack_bin)
                        .arg("--wim")
                        .arg(wim_path)
                        .arg("--include-list")
                        .arg(windows_rootfs_manifest)
                        .arg("--output")
                        .arg(staging),
                )?;
            }
        }
        write_manifest(extract_manifest, &extract_signature)?;
    }
    Ok(())
}

fn rootfs_extract_signature(
    windows_source: &WindowsSource,
    windows_rootfs_manifest: &Path,
    wimunpack_bin: &Path,
) -> Result<String, Box<dyn Error>> {
    let source_signature = match windows_source {
        WindowsSource::Iso(path) => format!("iso={}", file_signature(path)?),
        WindowsSource::Wim(path) => format!("wim={}", file_signature(path)?),
    };
    Ok(format!(
        "{}\ninclude_list={}\nwimunpack={}\n",
        source_signature,
        file_signature(windows_rootfs_manifest)?,
        file_signature(wimunpack_bin)?,
    ))
}

fn rootfs_build_signature(
    windows_source: Option<&WindowsSource>,
    windows_rootfs_manifest: Option<&Path>,
    rootfs_size_mib: &str,
    mkrootfs_bin: &Path,
) -> Result<String, Box<dyn Error>> {
    let mut signature = String::new();
    if let Some(manifest) = windows_rootfs_manifest {
        if let Some(source) = windows_source {
            match source {
                WindowsSource::Iso(path) => {
                    signature.push_str(&format!("iso={}\n", file_signature(path)?));
                }
                WindowsSource::Wim(path) => {
                    signature.push_str(&format!("wim={}\n", file_signature(path)?));
                }
            }
        }
        signature.push_str(&format!("include_list={}\n", file_signature(manifest)?));
    }
    signature.push_str(&format!("rootfs_size_mib={rootfs_size_mib}\n"));
    signature.push_str(&format!("mkrootfs={}\n", file_signature(mkrootfs_bin)?));
    signature.push_str("overlay=windows-real\n");
    Ok(signature)
}

fn fetch_uup_wim(
    root: &Path,
    uup_fetch_bin: &Path,
    config: &UupConfig,
) -> Result<PathBuf, Box<dyn Error>> {
    let mut cmd = Command::new(uup_fetch_bin);
    cmd.current_dir(root)
        .arg("--output-dir")
        .arg(&config.output_dir)
        .arg("--build")
        .arg(&config.build)
        .arg("--arch")
        .arg(&config.arch)
        .arg("--ring")
        .arg(&config.ring)
        .arg("--flight")
        .arg(&config.flight)
        .arg("--sku")
        .arg(&config.sku)
        .arg("--release-type")
        .arg(&config.release_type)
        .arg("--branch")
        .arg(&config.branch);

    if let Some(update_id) = config.update_id.as_ref() {
        cmd.arg("--update-id").arg(update_id);
    }
    if let Some(revision) = config.revision.as_ref() {
        cmd.arg("--revision").arg(revision);
    }

    eprintln!("info: fetching Windows image from Microsoft UUP endpoints");
    let output = run_cmd(&mut cmd)?;
    let path = output
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(PathBuf::from)
        .ok_or("uup_fetch did not return an output path")?;

    let resolved = if path.is_absolute() {
        path
    } else {
        root.join(path)
    };
    if !resolved.exists() {
        return Err(format!("uup_fetch output does not exist: {}", resolved.display()).into());
    }
    Ok(resolved)
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

fn copy_file(from: &Path, to: &Path) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(from, to)?;

    Ok(())
}

fn install_windows_real_init_to_dir(target_dir: &Path) -> Result<(), Box<dyn Error>> {
    let system32 = target_dir.join("Windows/System32");
    let autochk = system32.join("autochk.exe");
    if !autochk.exists() {
        return Err(format!(
            "windows rootfs requires {} in staged rootfs",
            autochk.display()
        )
        .into());
    }
    copy_file(&autochk, &system32.join("init.exe"))?;
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
