use clap::Parser;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::fmt;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const WIM_DENTRY_DISK_SIZE: usize = 102;
const WIM_EXTRA_STREAM_DISK_SIZE: usize = 38;

#[derive(Parser, Debug)]
#[command(about = "Unpack WIM from Windows ISO", long_about = None)]
struct Args {
    #[arg(short, long)]
    iso: PathBuf,

    #[arg(short, long)]
    output: PathBuf,

    #[arg(short, long, default_value = "sources/install.wim")]
    wim_path: String,

    #[arg(long = "include-path")]
    include_paths: Vec<String>,

    #[arg(long)]
    include_list: Option<PathBuf>,
}

#[derive(Debug)]
enum WimUnpackError {
    Io(std::io::Error),
    Iso(String),
    Wim(String),
    FileNotFound(String),
    Decompression(String),
}

impl fmt::Display for WimUnpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "IO error: {err}"),
            Self::Iso(err) => write!(f, "ISO parse error: {err}"),
            Self::Wim(err) => write!(f, "WIM parse error: {err}"),
            Self::FileNotFound(path) => write!(f, "File not found in ISO: {path}"),
            Self::Decompression(err) => write!(f, "Decompression error: {err}"),
        }
    }
}

impl std::error::Error for WimUnpackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for WimUnpackError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
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
    _unused: (),
}

#[derive(Debug, Clone, Copy)]
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

#[derive(Debug, Clone)]
struct LookupEntry {
    res_entry: ResEntry,
    part_number: u16,
    ref_count: u32,
    hash: [u8; 20],
}

fn read_exact_array<const N: usize, R: Read>(
    reader: &mut R,
) -> Result<[u8; N], WimUnpackError> {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_u16_from_reader<R: Read>(reader: &mut R) -> Result<u16, WimUnpackError> {
    Ok(u16::from_le_bytes(read_exact_array(reader)?))
}

fn read_u32_from_reader<R: Read>(reader: &mut R) -> Result<u32, WimUnpackError> {
    Ok(u32::from_le_bytes(read_exact_array(reader)?))
}

fn read_u64_from_reader<R: Read>(reader: &mut R) -> Result<u64, WimUnpackError> {
    Ok(u64::from_le_bytes(read_exact_array(reader)?))
}

fn read_res_entry<R: Read>(reader: &mut R) -> Result<ResEntry, WimUnpackError> {
    Ok(ResEntry {
        size_flags: read_u64_from_reader(reader)?,
        offset: read_u64_from_reader(reader)?,
        original_size: read_u64_from_reader(reader)?,
    })
}

fn read_wim_header<R: Read>(reader: &mut R) -> Result<WimHeader, WimUnpackError> {
    Ok(WimHeader {
        image_tag: read_exact_array(reader)?,
        size: read_u32_from_reader(reader)?,
        version: read_u32_from_reader(reader)?,
        flags: read_u32_from_reader(reader)?,
        compression_size: read_u32_from_reader(reader)?,
        guid: read_exact_array(reader)?,
        part_number: read_u16_from_reader(reader)?,
        total_parts: read_u16_from_reader(reader)?,
        image_count: read_u32_from_reader(reader)?,
        offset_table: read_res_entry(reader)?,
        xml_data: read_res_entry(reader)?,
        boot_metadata: read_res_entry(reader)?,
        boot_index: read_u32_from_reader(reader)?,
        integrity: read_res_entry(reader)?,
        _unused: {
            let mut unused = [0u8; 60];
            reader.read_exact(&mut unused)?;
            ()
        },
    })
}

fn read_lookup_entry<R: Read>(reader: &mut R) -> Result<LookupEntry, WimUnpackError> {
    Ok(LookupEntry {
        res_entry: read_res_entry(reader)?,
        part_number: read_u16_from_reader(reader)?,
        ref_count: read_u32_from_reader(reader)?,
        hash: read_exact_array(reader)?,
    })
}

fn main() -> Result<(), WimUnpackError> {
    let args = Args::parse();
    let include_paths = load_include_paths(&args)?;

    println!("Opening ISO: {}", args.iso.display());
    let mut wim_reader = open_wim_from_iso(&args.iso, &args.wim_path)?;
    println!("Found WIM in ISO");

    unpack_wim(
        &mut wim_reader,
        &args.iso,
        &args.wim_path,
        &args.output,
        include_paths.as_deref(),
    )?;

    Ok(())
}

trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

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

fn unpack_wim<R: Read + Seek>(
    wim: &mut R,
    iso_path: &Path,
    wim_path: &str,
    output: &Path,
    include_paths: Option<&[String]>,
) -> Result<(), WimUnpackError> {
    wim.seek(SeekFrom::Start(0))?;
    let header = read_wim_header(wim)?;
    if &header.image_tag != b"MSWIM\0\0\0" {
        return Err(WimUnpackError::Wim("Not a valid MSWIM file".to_string()));
    }

    let lookup_data = read_resource(wim, &header.offset_table, header.compression_size)
        .map_err(|err| WimUnpackError::Wim(format!("failed to read lookup table: {}", err)))?;
    let mut lookup_table = Vec::new();
    let mut lookup_reader = std::io::Cursor::new(lookup_data.as_slice());
    let entry_count = header.offset_table.original_size / 50;
    for _ in 0..entry_count {
        lookup_table.push(read_lookup_entry(&mut lookup_reader)?);
    }
    let lookup_by_hash: HashMap<[u8; 20], LookupEntry> = lookup_table
        .iter()
        .cloned()
        .filter(|entry| !entry.res_entry.is_metadata())
        .map(|entry| (entry.hash, entry))
        .collect();

    if header.image_count == 0 {
        return Err(WimUnpackError::Wim("No images in WIM".to_string()));
    }

    let metadata_res = lookup_table
        .iter()
        .find(|e| e.res_entry.is_metadata())
        .ok_or(WimUnpackError::Wim("Metadata not found".to_string()))?;

    let metadata = read_resource(wim, &metadata_res.res_entry, header.compression_size)
        .map_err(|err| WimUnpackError::Wim(format!("failed to read image metadata: {}", err)))?;

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

    tasks.par_iter().try_for_each_init(
        || open_wim_from_iso(&iso_path.to_path_buf(), wim_path),
        |reader, task| {
            let reader = reader
                .as_mut()
                .map_err(|err| WimUnpackError::Iso(err.to_string()))?;
            extract_blob_to_path(&mut **reader, task, header.compression_size)
        },
    )?;

    Ok(())
}

#[derive(Debug, Clone)]
struct ExtractTask {
    path: PathBuf,
    res_entry: ResEntry,
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

fn read_resource<R: Read + Seek + ?Sized>(
    wim: &mut R,
    res: &ResEntry,
    chunk_size: u32,
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
            let mut buf = [0u8; 4];
            wim.read_exact(&mut buf)?;
            chunk_offsets.push(u32::from_le_bytes(buf) as u64);
        } else {
            let mut buf = [0u8; 8];
            wim.read_exact(&mut buf)?;
            chunk_offsets.push(u64::from_le_bytes(buf));
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
        } else {
            wim_lzx::decompress(&chunk_data, out_chunk_size)
                .map_err(|err| WimUnpackError::Decompression(err.to_string()))?
        };
        output.extend_from_slice(&decompressed);
        previous_cumulative_size = cumulative_size;
    }

    Ok(output)
}

fn collect_tasks(
    metadata: &[u8],
    offset: u64,
    lookup_by_hash: &HashMap<[u8; 20], LookupEntry>,
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
        } else if let Some(entry) = lookup_by_hash.get(&dentry.hash) {
            if should_extract(&entry_relative_path, include_paths) {
                if let Some(parent) = path.parent() {
                    create_dir_all(parent)?;
                }
                tasks.push(ExtractTask {
                    path,
                    res_entry: entry.res_entry,
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

fn extract_blob_to_path<R: Read + Seek + ?Sized>(
    wim: &mut R,
    task: &ExtractTask,
    chunk_size: u32,
) -> Result<(), WimUnpackError> {
    let data = read_resource(wim, &task.res_entry, chunk_size).map_err(|err| {
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
