extern crate alloc;

use alloc::string::{String, ToString};
use spin::Lazy;

#[derive(Debug, Clone, Default)]
pub struct KernelParams {
    pub raw: String,
    pub init: Option<String>,
    pub root: Option<String>,
    pub rootfstype: Option<String>,
    pub debug: bool,
    pub quiet: bool,
    pub loglevel: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootDevice {
    VirtioBlk0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootFsType {
    Crabfs,
}

static KERNEL_PARAMS: Lazy<KernelParams> = Lazy::new(parse_kernel_params);

pub fn params() -> &'static KernelParams {
    &KERNEL_PARAMS
}

pub fn resolved_init_path() -> String {
    params()
        .init
        .clone()
        .unwrap_or_else(|| "\\SystemRoot\\System32\\init.exe".to_string())
}

pub fn resolved_root_device() -> Option<RootDevice> {
    match params().root.as_deref() {
        None => Some(RootDevice::VirtioBlk0),
        Some("/dev/vda" | "virtio-blk0" | "virtio0") => Some(RootDevice::VirtioBlk0),
        _ => None,
    }
}

pub fn resolved_root_fstype() -> Option<RootFsType> {
    match params().rootfstype.as_deref() {
        None => Some(RootFsType::Crabfs),
        Some("crabfs") => Some(RootFsType::Crabfs),
        _ => None,
    }
}

fn parse_kernel_params() -> KernelParams {
    let raw = "".to_string();

    let mut params = KernelParams {
        raw: raw.clone(),
        ..KernelParams::default()
    };

    for token in raw.split_ascii_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            match key {
                "init" => params.init = Some(value.to_string()),
                "root" => params.root = Some(value.to_string()),
                "rootfstype" => params.rootfstype = Some(value.to_string()),
                "loglevel" => {
                    if let Ok(level) = value.parse::<u8>() {
                        params.loglevel = Some(level.min(7));
                    }
                }
                _ => {}
            }
            continue;
        }

        match token {
            "debug" => params.debug = true,
            "quiet" => params.quiet = true,
            _ => {}
        }
    }

    params
}
