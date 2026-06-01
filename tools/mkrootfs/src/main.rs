use crabfs::device::StdFileDevice;
use crabfs::pack::{PackOptions, pack_from_directory};
use std::path::PathBuf;

fn main() -> Result<(), String> {
    let args = parse_args()?;
    let size_bytes = args.size_mib * 1024 * 1024;
    let mut dev =
        StdFileDevice::create(&args.output).map_err(|_| "failed to create image".to_string())?;
    dev.set_len(size_bytes)
        .map_err(|_| "failed to resize image".to_string())?;

    let report = pack_from_directory(
        &mut dev,
        &args.source,
        &PackOptions {
            total_blocks: size_bytes / 4096,
            block_size: 4096,
            sector_size: 512,
            uuid: [
                0x47, 0x45, 0x4e, 0x54, 0x4f, 0x4f, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
        },
    )
    .map_err(|err| format!("pack failed: {err}"))?;

    println!(
        "packed {} inodes into {} (skipped {})",
        report.packed_inodes,
        args.output.display(),
        report.skipped.len()
    );
    for skipped in report.skipped {
        println!("skipped {}", skipped.display());
    }
    Ok(())
}

struct Args {
    source: PathBuf,
    output: PathBuf,
    size_mib: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut source = None;
    let mut output = None;
    let mut size_mib = 256u64;
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--source" => source = iter.next().map(PathBuf::from),
            "--output" => output = iter.next().map(PathBuf::from),
            "--size-mib" => {
                let value = iter.next().ok_or("missing value for --size-mib")?;
                size_mib = value
                    .parse::<u64>()
                    .map_err(|_| "invalid integer for --size-mib".to_string())?;
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(Args {
        source: source.ok_or("missing --source")?,
        output: output.ok_or("missing --output")?,
        size_mib,
    })
}
