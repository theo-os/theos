use binrw::{BinReaderExt, binrw};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File as StdFile;
use std::fs::{File, create_dir_all};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use wim_lzms;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const WIM_DENTRY_DISK_SIZE: usize = 102;
const WIM_EXTRA_STREAM_DISK_SIZE: usize = 38;

// WIM header compression flags
const WIM_FLAG_COMPRESS_LZMS: u32 = 0x00080000;

// Solid WIM (WIMX) version
const WIM_VERSION_SOLID: u32 = 0xe00;

// Marker in blob table for solid resource entries
const SOLID_RESOURCE_MAGIC: u64 = 0x100000000;

#[derive(Parser, Debug)]
#[command(about = "Unpack WIM/ESD from Windows ISO or a direct ESD file", long_about = None)]
struct Args {
    /// Windows ISO to extract WIM from (mutually exclusive with --esd)
    #[arg(long)]
    iso: Option<PathBuf>,

    /// Direct ESD/WIM file path (skips ISO extraction step)
    #[arg(long, conflicts_with = "iso")]
    esd: Option<PathBuf>,

    #[arg(short, long)]
    output: PathBuf,

    #[arg(short, long, default_value = "sources/install.wim")]
    wim_path: String,

    #[arg(long = "include-path")]
    include_paths: Vec<String>,

    #[arg(long)]
    include_list: Option<PathBuf>,
}

#[derive(Error, Debug)]
enum WimUnpackError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ISO parse error: {0}")]
    Iso(String),
    #[error("WIM parse error: {0}")]
    Wim(String),
    #[error("File not found in ISO: {0}")]
    FileNotFound(String),
    #[error("BinRead error: {0}")]
    BinRead(String),
    #[error("Decompression error: {0}")]
    Decompression(String),
}

impl From<binrw::Error> for WimUnpackError {
    fn from(err: binrw::Error) -> Self {
        WimUnpackError::BinRead(format!("{:?}", err))
    }
}

#[binrw]
#[derive(Debug)]
#[br(little)]
struct WimHeader {
    image_tag: [u8; 8],
    size: u32,
    version: u32,
    flags: u32,
    compression_size: u32,
    guid: [u8; 16],
    part_number: u16,
    total_parts: u16,
    image_count: u32,
    offset_table: ResEntry,
    xml_data: ResEntry,
    boot_metadata: ResEntry,
    boot_index: u32,
    integrity: ResEntry,
    #[br(pad_before = 60)]
    _unused: (),
}

#[binrw]
#[derive(Debug, Clone, Copy)]
#[br(little)]
struct ResEntry {
    size_flags: u64,
    offset: u64,
    original_size: u64,
}

impl ResEntry {
    fn is_compressed(&self) -> bool {
        self.flags() & 0x04 != 0
    }

    fn is_metadata(&self) -> bool {
        self.flags() & 0x02 != 0
    }

    fn flags(&self) -> u8 {
        (self.size_flags >> 56) as u8
    }

    fn compressed_size(&self) -> u64 {
        self.size_flags & 0x00ff_ffff_ffff_ffff
    }
}

#[binrw]
#[derive(Debug, Clone)]
#[br(little)]
struct LookupEntry {
    res_entry: ResEntry,
    part_number: u16,
    ref_count: u32,
    hash: [u8; 20],
}

// Location of a blob in the WIM file.
#[derive(Clone, Debug)]
enum BlobLoc {
    // Regular (non-solid) resource.
    Regular(ResEntry),
    // Blob packed within a solid (LZMS) resource.
    Solid {
        // File offset of the solid resource's alt_chunk_table_header.
        res_file_offset: u64,
        // Compressed size of the entire solid resource on disk.
        res_compressed_size: u64,
        // Uncompressed size of the entire solid resource.
        res_uncompressed_size: u64,
        // Byte offset of this blob within the uncompressed solid resource.
        blob_offset: u64,
        // Uncompressed size of this blob.
        blob_size: u64,
    },
}

fn main() -> Result<(), WimUnpackError> {
    let args = Args::parse();
    let include_paths = load_include_paths(&args)?;

    if let Some(ref esd_path) = args.esd {
        println!("Opening ESD: {}", esd_path.display());
        let mut wim_reader = open_wim_file(esd_path)?;
        println!("Opened ESD");
        unpack_wim_direct(
            &mut wim_reader,
            esd_path,
            &args.output,
            include_paths.as_deref(),
        )?;
    } else {
        let iso = args.iso.as_ref().ok_or(WimUnpackError::Iso(
            "either --iso or --esd is required".into(),
        ))?;
        println!("Opening ISO: {}", iso.display());
        let mut wim_reader = open_wim_from_iso(iso, &args.wim_path)?;
        println!("Found WIM in ISO");
        unpack_wim(
            &mut wim_reader,
            iso,
            &args.wim_path,
            &args.output,
            include_paths.as_deref(),
        )?;
    }

    Ok(())
}

trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

fn open_wim_file(path: &Path) -> Result<Box<dyn ReadSeek>, WimUnpackError> {
    let file = StdFile::open(path)?;
    Ok(Box::new(file))
}

fn open_wim_from_iso(
    iso_path: &PathBuf,
    wim_path: &str,
) -> Result<Box<dyn ReadSeek>, WimUnpackError> {
    match iso9660::open_file(iso_path, wim_path) {
        Ok(reader) => Ok(Box::new(reader)),
        Err(iso9660::Error::FileNotFound(_)) => match udf::open_file(iso_path, wim_path) {
            Ok(reader) => Ok(Box::new(reader)),
            Err(udf::Error::FileNotFound(_)) => {
                Err(WimUnpackError::FileNotFound(wim_path.to_string()))
            }
            Err(err) => Err(WimUnpackError::Iso(err.to_string())),
        },
        Err(err) => Err(WimUnpackError::Iso(err.to_string())),
    }
}

/// Parse the blob table and return a hash→BlobLoc map (non-metadata blobs only)
/// and the list of metadata blob locations (in order).
fn parse_blob_table(
    wim: &mut dyn ReadSeek,
    header: &WimHeader,
) -> Result<(HashMap<[u8; 20], BlobLoc>, Vec<BlobLoc>), WimUnpackError> {
    // Read the raw blob table (uncompressed in the file for ESDs).
    let ot = &header.offset_table;
    let table_data = if !ot.is_compressed() || ot.compressed_size() == ot.original_size {
        let mut buf = vec![0u8; ot.original_size as usize];
        wim.seek(SeekFrom::Start(ot.offset))?;
        wim.read_exact(&mut buf)?;
        buf
    } else {
        read_resource_chunks(wim, ot, header.compression_size, header.flags)?
    };

    let n = table_data.len() / 50;
    let mut by_hash: HashMap<[u8; 20], BlobLoc> = HashMap::new();
    let mut metadata_locs: Vec<BlobLoc> = Vec::new();

    // Solid resource info discovered during a solid run.
    // (file_offset, compressed_size, uncompressed_size)
    let mut solid_resources: Vec<(u64, u64, u64)> = Vec::new();
    let mut in_solid_run = false;

    for i in 0..n {
        let off = i * 50;
        let sf = u64::from_le_bytes(table_data[off..off + 8].try_into().unwrap());
        let file_offset = u64::from_le_bytes(table_data[off + 8..off + 16].try_into().unwrap());
        let orig_size = u64::from_le_bytes(table_data[off + 16..off + 24].try_into().unwrap());
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&table_data[off + 30..off + 50]);
        let flags = (sf >> 56) as u8;
        let csz = sf & 0x00ff_ffff_ffff_ffff;

        if flags & 0x10 != 0 && header.version == WIM_VERSION_SOLID {
            // Solid entry.
            if !in_solid_run {
                in_solid_run = true;
                // Pre-scan to load all solid resource descriptors for this run.
                solid_resources = load_solid_resources(&table_data, i, n, wim)?;
            }

            if orig_size == SOLID_RESOURCE_MAGIC {
                // Resource marker — skip, info already in solid_resources.
                continue;
            }

            // Blob entry: assign to the right solid resource by cumulative offset.
            let mut cumulative = file_offset; // blob's offset_in_wim
            let blob_size = csz;
            for &(res_file_offset, res_compressed_size, res_uncompressed_size) in &solid_resources {
                if cumulative + blob_size <= res_uncompressed_size {
                    let loc = BlobLoc::Solid {
                        res_file_offset,
                        res_compressed_size,
                        res_uncompressed_size,
                        blob_offset: cumulative,
                        blob_size,
                    };
                    by_hash.insert(hash, loc);
                    break;
                }
                cumulative = cumulative.saturating_sub(res_uncompressed_size);
            }
        } else {
            // Regular (non-solid) entry.
            in_solid_run = false;
            solid_resources.clear();

            let res = ResEntry {
                size_flags: sf,
                offset: file_offset,
                original_size: orig_size,
            };
            if flags & 0x02 != 0 {
                metadata_locs.push(BlobLoc::Regular(res));
            } else {
                by_hash.insert(hash, BlobLoc::Regular(res));
            }
        }
    }

    Ok((by_hash, metadata_locs))
}

/// Pre-scan a solid run starting at `start_idx` to load solid resource
/// descriptors. Returns (file_offset, compressed_size, uncompressed_size).
fn load_solid_resources(
    table_data: &[u8],
    start_idx: usize,
    n: usize,
    wim: &mut dyn ReadSeek,
) -> Result<Vec<(u64, u64, u64)>, WimUnpackError> {
    let mut resources = Vec::new();
    for i in start_idx..n {
        let off = i * 50;
        let sf = u64::from_le_bytes(table_data[off..off + 8].try_into().unwrap());
        let file_offset = u64::from_le_bytes(table_data[off + 8..off + 16].try_into().unwrap());
        let orig_size = u64::from_le_bytes(table_data[off + 16..off + 24].try_into().unwrap());
        let flags = (sf >> 56) as u8;
        let csz = sf & 0x00ff_ffff_ffff_ffff;

        if flags & 0x10 == 0 {
            break; // End of solid run.
        }
        if orig_size == SOLID_RESOURCE_MAGIC {
            // Read alt_chunk_table_header to get uncompressed size.
            wim.seek(SeekFrom::Start(file_offset))?;
            let mut hdr = [0u8; 16];
            wim.read_exact(&mut hdr)?;
            let res_usize = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
            resources.push((file_offset, csz, res_usize));
        }
    }
    Ok(resources)
}

/// Read a solid blob: decompress only the needed chunks from the solid resource.
fn read_solid_blob(
    wim: &mut dyn ReadSeek,
    res_file_offset: u64,
    blob_offset: u64,
    blob_size: u64,
) -> Result<Vec<u8>, WimUnpackError> {
    // Read alt_chunk_table_header (16 bytes).
    wim.seek(SeekFrom::Start(res_file_offset))?;
    let mut hdr = [0u8; 16];
    wim.read_exact(&mut hdr)?;
    let res_usize = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
    let chunk_size = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as u64;
    let compression_format = u32::from_le_bytes(hdr[12..16].try_into().unwrap());

    let n_chunks = res_usize.div_ceil(chunk_size) as usize;

    // Read per-chunk compressed sizes (4 bytes each, alt format).
    let mut chunk_sizes = vec![0u32; n_chunks];
    let mut size_buf = vec![0u8; n_chunks * 4];
    wim.read_exact(&mut size_buf)?;
    for i in 0..n_chunks {
        chunk_sizes[i] = u32::from_le_bytes(size_buf[i * 4..i * 4 + 4].try_into().unwrap());
    }

    let data_start = res_file_offset + 16 + n_chunks as u64 * 4;

    let first_chunk = (blob_offset / chunk_size) as usize;
    let last_chunk = ((blob_offset + blob_size - 1) / chunk_size) as usize;

    // Compute file offset of first_chunk.
    let mut chunk_file_offset = data_start;
    for i in 0..first_chunk {
        chunk_file_offset += chunk_sizes[i] as u64;
    }

    // Decompress needed chunks and concatenate.
    let mut uncompressed = Vec::new();
    for ci in first_chunk..=last_chunk {
        let csz = chunk_sizes[ci] as usize;
        let usz = if ci == n_chunks - 1 {
            let rem = res_usize % chunk_size;
            if rem == 0 {
                chunk_size as usize
            } else {
                rem as usize
            }
        } else {
            chunk_size as usize
        };

        let mut chunk_data = vec![0u8; csz];
        wim.seek(SeekFrom::Start(chunk_file_offset))?;
        wim.read_exact(&mut chunk_data)?;
        chunk_file_offset += csz as u64;

        if csz == usz {
            uncompressed.extend_from_slice(&chunk_data);
        } else {
            let decompressed = match compression_format {
                3 => wim_lzms::decompress(&chunk_data, usz)
                    .map_err(|e| WimUnpackError::Decompression(e.to_string()))?,
                _ => {
                    return Err(WimUnpackError::Decompression(format!(
                        "unsupported solid compression format {compression_format}"
                    )));
                }
            };
            uncompressed.extend_from_slice(&decompressed);
        }
    }

    // Extract the blob's bytes from the decompressed chunk window.
    let window_start = first_chunk as u64 * chunk_size;
    let start_in_buf = (blob_offset - window_start) as usize;
    Ok(uncompressed[start_in_buf..start_in_buf + blob_size as usize].to_vec())
}

/// Unpack a WIM/ESD given as a direct file path (no ISO wrapper).
fn unpack_wim_direct(
    mut wim: &mut dyn ReadSeek,
    esd_path: &Path,
    output: &Path,
    include_paths: Option<&[String]>,
) -> Result<(), WimUnpackError> {
    wim.seek(SeekFrom::Start(0))?;
    let header: WimHeader = wim.read_le()?;
    if &header.image_tag != b"MSWIM\0\0\0" {
        return Err(WimUnpackError::Wim("Not a valid MSWIM file".to_string()));
    }

    let (lookup_by_hash, metadata_locs) = parse_blob_table(wim, &header)?;

    if metadata_locs.is_empty() {
        return Err(WimUnpackError::Wim("No metadata in WIM".to_string()));
    }

    create_dir_all(output)?;

    // Try each metadata image until we find one with matching files.
    let esd_path_buf = esd_path.to_path_buf();
    let mut tasks = Vec::new();
    for meta_loc in &metadata_locs {
        let metadata = read_blob(wim, meta_loc, header.compression_size, header.flags)?;
        let total_security_size = align_u64(read_u32_le(&metadata, 0)? as u64, 8);
        let mut image_tasks = Vec::new();
        collect_tasks(
            &metadata,
            total_security_size,
            &lookup_by_hash,
            output,
            Path::new(""),
            include_paths,
            &mut image_tasks,
        )?;
        if !image_tasks.is_empty() {
            tasks = image_tasks;
            break;
        }
    }

    let pb = Arc::new(make_progress_bar(tasks.len()));
    tasks.par_iter().try_for_each_init(
        || open_wim_file(&esd_path_buf),
        |reader, task| {
            let reader = reader
                .as_mut()
                .map_err(|e| WimUnpackError::Iso(e.to_string()))?;
            let result = extract_task(&mut **reader, task, header.compression_size, header.flags);
            pb.inc(1);
            result
        },
    )?;
    pb.finish_and_clear();

    Ok(())
}

fn unpack_wim<R: Read + Seek + Send>(
    wim: &mut R,
    iso_path: &Path,
    wim_path: &str,
    output: &Path,
    include_paths: Option<&[String]>,
) -> Result<(), WimUnpackError> {
    wim.seek(SeekFrom::Start(0))?;
    let header: WimHeader = wim.read_le()?;
    if &header.image_tag != b"MSWIM\0\0\0" {
        return Err(WimUnpackError::Wim("Not a valid MSWIM file".to_string()));
    }

    let (lookup_by_hash, metadata_locs) = parse_blob_table(wim, &header)?;

    if metadata_locs.is_empty() {
        return Err(WimUnpackError::Wim("No metadata in WIM".to_string()));
    }

    let metadata = read_blob(
        wim,
        &metadata_locs[0],
        header.compression_size,
        header.flags,
    )?;
    let total_security_size = align_u64(read_u32_le(&metadata, 0)? as u64, 8);
    create_dir_all(output)?;

    let mut tasks = Vec::new();
    collect_tasks(
        &metadata,
        total_security_size,
        &lookup_by_hash,
        output,
        Path::new(""),
        include_paths,
        &mut tasks,
    )?;

    let flags = header.flags;
    let chunk_size = header.compression_size;
    let pb = Arc::new(make_progress_bar(tasks.len()));
    tasks.par_iter().try_for_each_init(
        || open_wim_from_iso(&iso_path.to_path_buf(), wim_path),
        |reader, task| {
            let reader = reader
                .as_mut()
                .map_err(|err| WimUnpackError::Iso(err.to_string()))?;
            let result = extract_task(&mut **reader, task, chunk_size, flags);
            pb.inc(1);
            result
        },
    )?;
    pb.finish_and_clear();

    Ok(())
}

#[derive(Debug, Clone)]
struct ExtractTask {
    path: PathBuf,
    loc: BlobLoc,
}

fn align_u64(value: u64, align: u64) -> u64 {
    if value == 0 {
        0
    } else {
        (value + align - 1) & !(align - 1)
    }
}

fn read_bytes<'a>(buf: &'a [u8], offset: usize, len: usize) -> Result<&'a [u8], WimUnpackError> {
    buf.get(offset..offset + len).ok_or_else(|| {
        WimUnpackError::Wim(format!(
            "metadata buffer too short while reading {} bytes at offset {}",
            len, offset
        ))
    })
}

fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, WimUnpackError> {
    let bytes = read_bytes(buf, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, WimUnpackError> {
    let bytes = read_bytes(buf, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64, WimUnpackError> {
    let bytes = read_bytes(buf, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_utf16le_string(buf: &[u8], offset: usize, len: usize) -> Result<String, WimUnpackError> {
    if len == 0 {
        return Ok(String::new());
    }
    if len % 2 != 0 {
        return Err(WimUnpackError::Wim(format!(
            "invalid UTF-16LE string length {} at offset {}",
            len, offset
        )));
    }
    let bytes = read_bytes(buf, offset, len)?;
    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&utf16))
}

#[derive(Debug)]
struct Dentry {
    name: String,
    attributes: u32,
    hash: [u8; 20],
    subdir_offset: u64,
    next_offset: u64,
}

fn read_dentry(metadata: &[u8], offset: u64) -> Result<Option<Dentry>, WimUnpackError> {
    let offset = usize::try_from(offset)
        .map_err(|_| WimUnpackError::Wim("metadata offset does not fit in usize".to_string()))?;
    let stored_length = read_u64_le(metadata, offset)?;
    let length = align_u64(stored_length, 8);
    if length <= 8 {
        return Ok(None);
    }
    let length = usize::try_from(length)
        .map_err(|_| WimUnpackError::Wim("dentry length does not fit in usize".to_string()))?;
    if length < WIM_DENTRY_DISK_SIZE {
        return Err(WimUnpackError::Wim(format!(
            "invalid dentry length {} at offset {}",
            length, offset
        )));
    }
    let dentry_bytes = read_bytes(metadata, offset, length)?;

    let attributes = read_u32_le(dentry_bytes, 8)?;
    let subdir_offset = read_u64_le(dentry_bytes, 16)?;
    let num_extra_streams = read_u16_le(dentry_bytes, 96)? as usize;
    let short_name_len = read_u16_le(dentry_bytes, 98)? as usize;
    let name_len = read_u16_le(dentry_bytes, 100)? as usize;
    if short_name_len % 2 != 0 || name_len % 2 != 0 {
        return Err(WimUnpackError::Wim(format!(
            "invalid dentry name lengths at offset {}",
            offset
        )));
    }

    let mut cursor = WIM_DENTRY_DISK_SIZE;
    let name = read_utf16le_string(dentry_bytes, cursor, name_len)?;
    if name_len != 0 {
        cursor += name_len + 2;
    }
    if short_name_len != 0 {
        let _short_name = read_utf16le_string(dentry_bytes, cursor, short_name_len)?;
        cursor += short_name_len + 2;
    }
    if cursor > length {
        return Err(WimUnpackError::Wim(format!(
            "dentry variable data overruns fixed length at offset {}",
            offset
        )));
    }

    let mut next_offset = offset as u64 + length as u64;
    for _ in 0..num_extra_streams {
        let stream_offset = usize::try_from(next_offset).map_err(|_| {
            WimUnpackError::Wim("extra stream offset does not fit in usize".to_string())
        })?;
        let stream_len = align_u64(read_u64_le(metadata, stream_offset)?, 8);
        let stream_len = usize::try_from(stream_len).map_err(|_| {
            WimUnpackError::Wim("extra stream length does not fit in usize".to_string())
        })?;
        if stream_len < WIM_EXTRA_STREAM_DISK_SIZE {
            return Err(WimUnpackError::Wim(format!(
                "invalid extra stream length {} at offset {}",
                stream_len, stream_offset
            )));
        }
        let stream_name_len = read_u16_le(metadata, stream_offset + 36)? as usize;
        if stream_name_len % 2 != 0 || WIM_EXTRA_STREAM_DISK_SIZE + stream_name_len > stream_len {
            return Err(WimUnpackError::Wim(format!(
                "invalid extra stream name length {} at offset {}",
                stream_name_len, stream_offset
            )));
        }
        read_bytes(metadata, stream_offset, stream_len)?;
        next_offset += stream_len as u64;
    }

    let hash_bytes = read_bytes(dentry_bytes, 64, 20)?;
    let mut hash = [0u8; 20];
    hash.copy_from_slice(hash_bytes);

    Ok(Some(Dentry {
        name,
        attributes,
        hash,
        subdir_offset,
        next_offset,
    }))
}

/// Read a blob from any location (regular or solid).
fn read_blob(
    wim: &mut dyn ReadSeek,
    loc: &BlobLoc,
    chunk_size: u32,
    wim_flags: u32,
) -> Result<Vec<u8>, WimUnpackError> {
    match loc {
        BlobLoc::Regular(res) => read_resource_chunks(wim, res, chunk_size, wim_flags),
        BlobLoc::Solid {
            res_file_offset,
            blob_offset,
            blob_size,
            ..
        } => read_solid_blob(wim, *res_file_offset, *blob_offset, *blob_size),
    }
}

fn read_resource_chunks<R: Read + Seek + ?Sized>(
    mut wim: &mut R,
    res: &ResEntry,
    chunk_size: u32,
    wim_flags: u32,
) -> Result<Vec<u8>, WimUnpackError> {
    if !res.is_compressed() || res.compressed_size() == res.original_size {
        let mut buf = vec![0u8; res.original_size as usize];
        wim.seek(SeekFrom::Start(res.offset))?;
        wim.read_exact(&mut buf)?;
        return Ok(buf);
    }

    let num_chunks = (res.original_size + chunk_size as u64 - 1) / chunk_size as u64;
    let chunk_table_entries = num_chunks.saturating_sub(1);
    let mut chunk_offsets = Vec::with_capacity(chunk_table_entries as usize);
    wim.seek(SeekFrom::Start(res.offset))?;

    let entry_size: u64 = if res.original_size > 0x100000000 {
        8
    } else {
        4
    };
    for _ in 0..chunk_table_entries {
        if entry_size == 4 {
            chunk_offsets.push(wim.read_le::<u32>()? as u64);
        } else {
            chunk_offsets.push(wim.read_le::<u64>()? as u64);
        }
    }

    let mut output = Vec::with_capacity(res.original_size as usize);
    let table_len = chunk_table_entries * entry_size;
    let compressed_data_len = res
        .compressed_size()
        .checked_sub(table_len)
        .ok_or_else(|| {
            WimUnpackError::Wim("Compressed resource size smaller than table".to_string())
        })?;
    let mut previous_cumulative_size = 0u64;

    for i in 0..num_chunks {
        let cumulative_size = if i == num_chunks - 1 {
            compressed_data_len
        } else {
            chunk_offsets[i as usize]
        };
        let compressed_chunk_size = (cumulative_size - previous_cumulative_size) as usize;

        let mut chunk_data = vec![0u8; compressed_chunk_size];
        wim.seek(SeekFrom::Start(
            res.offset + table_len + previous_cumulative_size,
        ))?;
        wim.read_exact(&mut chunk_data)?;

        let out_chunk_size = if i == num_chunks - 1 {
            let rem = res.original_size % chunk_size as u64;
            if rem == 0 {
                chunk_size as usize
            } else {
                rem as usize
            }
        } else {
            chunk_size as usize
        };

        let decompressed = if compressed_chunk_size == out_chunk_size {
            chunk_data
        } else if wim_flags & WIM_FLAG_COMPRESS_LZMS != 0 {
            wim_lzms::decompress(&chunk_data, out_chunk_size)
                .map_err(|err| WimUnpackError::Decompression(err.to_string()))?
        } else {
            wim_lzx::decompress(&chunk_data, out_chunk_size)
                .map_err(|err| WimUnpackError::Decompression(err.to_string()))?
        };
        output.extend_from_slice(&decompressed);
        previous_cumulative_size = cumulative_size;
    }

    Ok(output)
}

fn extract_task(
    wim: &mut dyn ReadSeek,
    task: &ExtractTask,
    chunk_size: u32,
    wim_flags: u32,
) -> Result<(), WimUnpackError> {
    let data = read_blob(wim, &task.loc, chunk_size, wim_flags).map_err(|err| {
        WimUnpackError::Wim(format!(
            "failed to read blob for {}: {}",
            task.path.display(),
            err
        ))
    })?;
    if let Some(parent) = task.path.parent() {
        create_dir_all(parent)?;
    }
    let mut f = File::create(&task.path)?;
    f.write_all(&data)?;
    Ok(())
}

fn collect_tasks(
    metadata: &[u8],
    offset: u64,
    lookup_by_hash: &HashMap<[u8; 20], BlobLoc>,
    output_path: &Path,
    relative_path: &Path,
    include_paths: Option<&[String]>,
    tasks: &mut Vec<ExtractTask>,
) -> Result<(), WimUnpackError> {
    let Some(dentry) = read_dentry(metadata, offset)? else {
        return Ok(());
    };

    let entry_relative_path = if dentry.name.is_empty() {
        relative_path.to_path_buf()
    } else {
        relative_path.join(&dentry.name)
    };

    if !dentry.name.is_empty() {
        let path = output_path.join(&dentry.name);
        if dentry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            if should_descend(&entry_relative_path, include_paths) {
                create_dir_all(&path)?;
            }
        } else if let Some(loc) = lookup_by_hash.get(&dentry.hash) {
            if should_extract(&entry_relative_path, include_paths) {
                if let Some(parent) = path.parent() {
                    create_dir_all(parent)?;
                }
                tasks.push(ExtractTask {
                    path,
                    loc: loc.clone(),
                });
            }
        }
    }

    if dentry.subdir_offset != 0 && should_descend(&entry_relative_path, include_paths) {
        let mut child_offset = dentry.subdir_offset;
        loop {
            let Some(child) = read_dentry(metadata, child_offset)? else {
                break;
            };
            let child_output_path = output_path.join(&dentry.name);
            collect_tasks(
                metadata,
                child_offset,
                lookup_by_hash,
                if dentry.name.is_empty() {
                    output_path
                } else {
                    &child_output_path
                },
                &entry_relative_path,
                include_paths,
                tasks,
            )?;
            child_offset = child.next_offset;
        }
    }

    Ok(())
}

fn make_progress_bar(total: usize) -> ProgressBar {
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files")
            .unwrap()
            .progress_chars("=> "),
    );
    pb
}

fn load_include_paths(args: &Args) -> Result<Option<Vec<String>>, WimUnpackError> {
    let mut include_paths = Vec::new();
    if let Some(include_list) = &args.include_list {
        let contents = std::fs::read_to_string(include_list)?;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            include_paths.push(normalize_include_path(trimmed));
        }
    }
    include_paths.extend(
        args.include_paths
            .iter()
            .map(|path| normalize_include_path(path)),
    );
    if include_paths.is_empty() {
        Ok(None)
    } else {
        include_paths.sort();
        include_paths.dedup();
        Ok(Some(include_paths))
    }
}

fn normalize_include_path(path: &str) -> String {
    path.trim_matches('/')
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn should_extract(path: &Path, include_paths: Option<&[String]>) -> bool {
    let Some(include_paths) = include_paths else {
        return true;
    };
    let normalized = normalize_relative_path(path);
    include_paths.iter().any(|include| include == &normalized)
}

fn should_descend(path: &Path, include_paths: Option<&[String]>) -> bool {
    let Some(include_paths) = include_paths else {
        return true;
    };
    let normalized = normalize_relative_path(path);
    if normalized.is_empty() {
        return true;
    }
    include_paths.iter().any(|include| {
        include == &normalized
            || include
                .strip_prefix(&normalized)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn normalize_relative_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
        .to_ascii_lowercase()
}
