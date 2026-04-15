#![cfg(feature = "std")]

use crate::crc::write_xfs_crc;
use crate::device::BlockDevice;
use crate::error::{DeviceError, WriteError};
use crate::on_disk::inode::{
    Inode, InodeFormat, XFS_DINODE_CRC_OFF, XFS_DINODE_MAGIC, XFS_DINODE_SIZE_V3,
};
use crate::on_disk::superblock::Superblock;
use crate::reader;
use crate::writer::{MkfsOptions, mkfs};
use std::fs;
use std::path::{Path, PathBuf};
use std::string::String;
use std::vec;
use std::vec::Vec;

const INODE_TABLE_START_BLOCK: u64 = 8;
const INODES_PER_BLOCK: u64 = 8;
const LOCAL_FORK_BYTES: usize = 512 - XFS_DINODE_SIZE_V3;
pub const CRABFS_EXTENT_DIR_MAGIC: [u8; 8] = *b"CDIR0001";

#[derive(Debug, Clone)]
pub struct PackOptions {
    pub total_blocks: u64,
    pub block_size: u32,
    pub sector_size: u16,
    pub uuid: [u8; 16],
}

#[derive(Debug, Default, Clone)]
pub struct PackReport {
    pub packed_inodes: usize,
    pub skipped: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct PackedEntry {
    name: String,
    inode_index: usize,
    ftype: u8,
}

#[derive(Debug, Clone)]
enum NodeKind {
    Directory { entries: Vec<PackedEntry> },
    File { data: Vec<u8> },
    Symlink { target: Vec<u8> },
}

#[derive(Debug, Clone)]
struct Node {
    parent_index: usize,
    mode: u16,
    uid: u32,
    gid: u32,
    kind: NodeKind,
}

impl Node {
    fn inode_mode(&self) -> u16 {
        self.mode
    }
}

#[cfg(unix)]
fn metadata_mode(meta: &fs::Metadata) -> u16 {
    meta.mode() as u16
}

#[cfg(not(unix))]
fn metadata_mode(meta: &fs::Metadata) -> u16 {
    let file_type = meta.file_type();
    if file_type.is_dir() {
        0o040755
    } else if file_type.is_symlink() {
        0o120777
    } else {
        0o100644
    }
}

#[cfg(unix)]
fn metadata_uid(meta: &fs::Metadata) -> u32 {
    meta.uid()
}

#[cfg(not(unix))]
fn metadata_uid(_meta: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn metadata_gid(meta: &fs::Metadata) -> u32 {
    meta.gid()
}

#[cfg(not(unix))]
fn metadata_gid(_meta: &fs::Metadata) -> u32 {
    0
}

pub fn pack_from_directory<D: BlockDevice>(
    dev: &mut D,
    source: &Path,
    opts: &PackOptions,
) -> Result<PackReport, WriteError> {
    let mkfs_opts = MkfsOptions {
        block_size: opts.block_size,
        sector_size: opts.sector_size,
        ag_blocks: u32::try_from(opts.total_blocks)?,
        total_blocks: opts.total_blocks,
        uuid: opts.uuid,
    };
    mkfs(dev, &mkfs_opts)?;

    let sb = reader::read_superblock(dev).map_err(|err| match err {
        crate::error::ReadError::Device(dev_err) => WriteError::Device(dev_err),
        crate::error::ReadError::Parse(parse_err) => WriteError::Parse(parse_err),
    })?;

    let mut report = PackReport::default();
    let mut nodes = Vec::new();
    collect_tree(source, source, 0, String::new(), &mut nodes, &mut report)?;
    if nodes.is_empty() {
        nodes.push(Node {
            parent_index: 0,
            mode: 0o040755,
            uid: 0,
            gid: 0,
            kind: NodeKind::Directory {
                entries: Vec::new(),
            },
        });
    }

    let inode_count = u64::try_from(nodes.len())?;
    let inode_blocks = inode_count.div_ceil(INODES_PER_BLOCK);
    let mut next_data_block = INODE_TABLE_START_BLOCK + inode_blocks;

    let mut data_payloads = Vec::with_capacity(nodes.len());
    for index in 0..nodes.len() {
        let payload = build_payload(&nodes, index, &sb)?;
        let blocks = if payload.is_empty() {
            0
        } else {
            u64::try_from(payload.len())?.div_ceil(u64::from(sb.block_size))
        };
        let start_block = if blocks == 0 {
            0
        } else {
            let start = next_data_block;
            next_data_block = next_data_block.saturating_add(blocks);
            start
        };
        data_payloads.push((payload, start_block, blocks));
    }

    if next_data_block > opts.total_blocks {
        return Err(WriteError::Device(DeviceError::OutOfRange));
    }

    for (payload, start_block, blocks) in &data_payloads {
        if *blocks == 0 {
            continue;
        }
        write_data_blocks(dev, &sb, *start_block, payload)?;
    }

    for (index, node) in nodes.iter().enumerate() {
        let (payload, start_block, blocks) = &data_payloads[index];
        let inode_number = inode_number(&sb, index)?;
        let format = if payload.len() <= LOCAL_FORK_BYTES {
            InodeFormat::Local
        } else {
            InodeFormat::Extents
        };
        write_inode_record(
            dev,
            &sb,
            inode_number,
            node,
            payload,
            format,
            *start_block,
            *blocks,
        )?;
        report.packed_inodes += 1;
    }

    Ok(report)
}

fn collect_tree(
    root: &Path,
    path: &Path,
    parent_index: usize,
    _name: String,
    nodes: &mut Vec<Node>,
    report: &mut PackReport,
) -> Result<usize, WriteError> {
    let meta = fs::symlink_metadata(path).map_err(|_| WriteError::Device(DeviceError::Io))?;
    let mode = metadata_mode(&meta);
    let uid = metadata_uid(&meta);
    let gid = metadata_gid(&meta);

    let placeholder = Node {
        parent_index,
        mode,
        uid,
        gid,
        kind: NodeKind::Directory {
            entries: Vec::new(),
        },
    };
    let index = nodes.len();
    nodes.push(placeholder);

    let file_type = meta.file_type();
    if file_type.is_dir() {
        let mut entries = Vec::new();
        let mut children = fs::read_dir(path)
            .map_err(|_| WriteError::Device(DeviceError::Io))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WriteError::Device(DeviceError::Io))?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let child_path = child.path();
            let child_name = child.file_name().to_string_lossy().into_owned();
            let child_meta = fs::symlink_metadata(&child_path)
                .map_err(|_| WriteError::Device(DeviceError::Io))?;
            if !(child_meta.file_type().is_dir()
                || child_meta.file_type().is_file()
                || child_meta.file_type().is_symlink())
            {
                report.skipped.push(child_path);
                continue;
            }
            let child_index =
                collect_tree(root, &child_path, index, child_name.clone(), nodes, report)?;
            entries.push(PackedEntry {
                name: child_name,
                inode_index: child_index,
                ftype: dir_ftype(&nodes[child_index]),
            });
        }
        nodes[index].kind = NodeKind::Directory { entries };
    } else if file_type.is_symlink() {
        let target = fs::read_link(path)
            .map_err(|_| WriteError::Device(DeviceError::Io))?
            .to_string_lossy()
            .into_owned()
            .into_bytes();
        nodes[index].kind = NodeKind::Symlink { target };
    } else if file_type.is_file() {
        let data = fs::read(path).map_err(|_| WriteError::Device(DeviceError::Io))?;
        nodes[index].kind = NodeKind::File { data };
    } else {
        report
            .skipped
            .push(path.strip_prefix(root).unwrap_or(path).to_path_buf());
    }

    Ok(index)
}

fn dir_ftype(node: &Node) -> u8 {
    match node.kind {
        NodeKind::Directory { .. } => 2,
        NodeKind::File { .. } => 1,
        NodeKind::Symlink { .. } => 7,
    }
}

fn inode_number(sb: &Superblock, index: usize) -> Result<u64, WriteError> {
    Ok(sb.rootino + u64::try_from(index)?)
}

fn build_payload(nodes: &[Node], index: usize, sb: &Superblock) -> Result<Vec<u8>, WriteError> {
    Ok(match &nodes[index].kind {
        NodeKind::Directory { entries } => {
            let parent_ino = inode_number(sb, nodes[index].parent_index)?;
            let mut shortform = None;
            if entries.len() <= usize::from(u8::MAX) {
                let mut candidate = Vec::new();
                candidate.push(u8::try_from(entries.len())?);
                candidate.push(1);
                candidate.extend_from_slice(&parent_ino.to_be_bytes());
                for (slot, entry) in entries.iter().enumerate() {
                    let ino = inode_number(sb, entry.inode_index)?;
                    let name = entry.name.as_bytes();
                    candidate.push(u8::try_from(name.len())?);
                    candidate.extend_from_slice(&(u16::try_from(slot + 1)?).to_be_bytes());
                    candidate.extend_from_slice(name);
                    candidate.push(entry.ftype);
                    candidate.extend_from_slice(&ino.to_be_bytes());
                }
                if candidate.len() <= LOCAL_FORK_BYTES {
                    shortform = Some(candidate);
                }
            }
            if let Some(shortform) = shortform {
                shortform
            } else {
                let mut extent = Vec::new();
                extent.extend_from_slice(&CRABFS_EXTENT_DIR_MAGIC);
                extent.extend_from_slice(&(u32::try_from(entries.len())?).to_be_bytes());
                extent.extend_from_slice(&parent_ino.to_be_bytes());
                for entry in entries {
                    let ino = inode_number(sb, entry.inode_index)?;
                    let name = entry.name.as_bytes();
                    extent.extend_from_slice(&ino.to_be_bytes());
                    extent.push(entry.ftype);
                    extent.extend_from_slice(&(u16::try_from(name.len())?).to_be_bytes());
                    extent.extend_from_slice(name);
                }
                extent
            }
        }
        NodeKind::File { data } => data.clone(),
        NodeKind::Symlink { target } => target.clone(),
    })
}

fn write_data_blocks<D: BlockDevice>(
    dev: &mut D,
    sb: &Superblock,
    start_block: u64,
    payload: &[u8],
) -> Result<(), WriteError> {
    let block_size = sb.block_size as usize;
    let blocks = payload.len().div_ceil(block_size);
    for block_idx in 0..blocks {
        let start = block_idx * block_size;
        let end = payload.len().min(start + block_size);
        let mut block = vec![0u8; block_size];
        block[..end - start].copy_from_slice(&payload[start..end]);
        dev.write_at(
            (start_block + u64::try_from(block_idx)?) * u64::from(sb.block_size),
            &block,
        )?;
    }
    Ok(())
}

fn write_inode_record<D: BlockDevice>(
    dev: &mut D,
    sb: &Superblock,
    inode_number: u64,
    node: &Node,
    payload: &[u8],
    format: InodeFormat,
    start_block: u64,
    blocks: u64,
) -> Result<(), WriteError> {
    let inode_offset = u64::from(sb.block_size) * INODE_TABLE_START_BLOCK
        + (inode_number - sb.rootino) * u64::from(sb.inode_size);
    let mut raw = vec![0u8; sb.inode_size as usize];
    let inode = Inode {
        magic: XFS_DINODE_MAGIC,
        mode: node.inode_mode(),
        version: 3,
        format,
        onlink: 0,
        uid: node.uid,
        gid: node.gid,
        nlink: match node.kind {
            NodeKind::Directory { .. } => 2,
            _ => 1,
        },
        projid: 0,
        flushiter: 0,
        atime: (0, 0),
        mtime: (0, 0),
        ctime: (0, 0),
        size: i64::try_from(payload.len())?,
        nblocks: blocks,
        extsize: 0,
        nextents: if matches!(format, InodeFormat::Extents) {
            1
        } else {
            0
        },
        anextents: 0,
        forkoff: 0,
        aformat: InodeFormat::Extents,
        dmevmask: 0,
        dmstate: 0,
        flags: 0,
        generation: 0,
        next_unlinked: 0xffff_ffff,
        crc: 0,
        change_count: 0,
        lsn: 0,
        flags2: 0,
        cowextsize: 0,
        crtime: (0, 0),
        ino: inode_number,
        uuid: sb.uuid,
    };
    inode.serialize(&mut raw[..XFS_DINODE_SIZE_V3])?;
    match format {
        InodeFormat::Local => {
            raw[XFS_DINODE_SIZE_V3..XFS_DINODE_SIZE_V3 + payload.len()].copy_from_slice(payload);
        }
        InodeFormat::Extents => {
            serialize_bmap_extent(
                &mut raw[XFS_DINODE_SIZE_V3..XFS_DINODE_SIZE_V3 + 16],
                0,
                start_block,
                u32::try_from(blocks)?,
            )?;
        }
        _ => {}
    }
    write_xfs_crc(&mut raw[..sb.inode_size as usize], XFS_DINODE_CRC_OFF);
    dev.write_at(inode_offset, &raw[..sb.inode_size as usize])?;
    Ok(())
}

fn serialize_bmap_extent(
    out: &mut [u8],
    startoff: u64,
    startblock: u64,
    blockcount: u32,
) -> Result<(), WriteError> {
    let x0 = (startoff << 9) | ((startblock >> 43) & 0x1ff);
    let x1 = ((startblock & ((1u64 << 43) - 1)) << 21) | u64::from(blockcount);
    out[..8].copy_from_slice(&x0.to_be_bytes());
    out[8..16].copy_from_slice(&x1.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::BlockDevice;
    use std::fs::{self, File};
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct MemDevice {
        data: Vec<u8>,
    }

    impl BlockDevice for MemDevice {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), DeviceError> {
            let start = usize::try_from(offset).unwrap();
            let end = start + buf.len();
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), DeviceError> {
            let start = usize::try_from(offset).unwrap();
            let end = start + buf.len();
            self.data[start..end].copy_from_slice(buf);
            Ok(())
        }
    }

    #[test]
    fn packs_dirs_files_and_symlinks() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("crabfs-pack-{}", unique));
        fs::create_dir_all(root.join("bin")).unwrap();
        let mut file = File::create(root.join("bin/hello")).unwrap();
        writeln!(file, "hello world").unwrap();
        std::os::unix::fs::symlink("/bin/hello", root.join("hello-link")).unwrap();

        let mut dev = MemDevice {
            data: vec![0u8; 8 * 1024 * 1024],
        };
        let report = pack_from_directory(
            &mut dev,
            &root,
            &PackOptions {
                total_blocks: 2048,
                block_size: 4096,
                sector_size: 512,
                uuid: [7u8; 16],
            },
        )
        .unwrap();
        assert!(report.packed_inodes >= 3);

        let sb = reader::read_superblock(&mut dev).unwrap();
        let root_entries = reader::list_dir_entries(&mut dev, &sb, sb.rootino).unwrap();
        assert!(root_entries.iter().any(|entry| entry.name == "bin"));
        assert!(root_entries.iter().any(|entry| entry.name == "hello-link"));

        fs::remove_dir_all(root).unwrap();
    }
}
