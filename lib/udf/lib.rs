use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use thiserror::Error;

const SECTOR_SIZE: u64 = 2048;
const TAGID_ANCHOR: u16 = 0x0002;
const TAGID_PARTITION: u16 = 0x0005;
const TAGID_LOGICAL_VOLUME: u16 = 0x0006;
const TAGID_TERMINATING: u16 = 0x0008;
const TAGID_FILE_SET: u16 = 0x0100;
const TAGID_FILE_IDENTIFIER: u16 = 0x0101;
const TAGID_FILE_ENTRY: u16 = 0x0105;
const TAGID_EXTENDED_FILE_ENTRY: u16 = 0x010A;
const FILE_CHARACTERISTIC_DIRECTORY: u8 = 1 << 1;
const FILE_CHARACTERISTIC_PARENT: u8 = 1 << 3;
const ICBTAG_FILE_TYPE_DIRECTORY: u8 = 0x04;
const ICBTAG_FILE_TYPE_REGULAR: u8 = 0x05;
const ICBTAG_FLAG_AD_MASK: u16 = 0x0007;
const ICBTAG_FLAG_AD_SHORT: u16 = 0x0000;
const ICBTAG_FLAG_AD_LONG: u16 = 0x0001;
const ICBTAG_FLAG_AD_IN_ICB: u16 = 0x0003;
const UDF_LENGTH_MASK: u32 = 0x3fff_ffff;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a valid UDF image")]
    InvalidImage,
    #[error("unsupported UDF feature: {0}")]
    Unsupported(&'static str),
    #[error("path not found in UDF image: {0}")]
    FileNotFound(String),
}

#[derive(Clone, Copy, Debug)]
struct LongAd {
    len: u32,
    lba: u32,
    partition: u16,
}

#[derive(Clone, Copy, Debug)]
struct PartitionInfo {
    number: u16,
    start_lba: u32,
}

#[derive(Debug)]
struct FileEntryInfo {
    file_type: u8,
    flags: u16,
    info_len: u64,
    allocation_descriptors: Vec<u8>,
    inline_data: Vec<u8>,
}

#[derive(Debug)]
struct FileIdentifier {
    name: String,
    icb: LongAd,
    characteristics: u8,
}

pub struct FileReader {
    inner: File,
    extents: Vec<(u64, u64)>,
    len: u64,
    pos: u64,
}

impl FileReader {
    fn new(inner: File, extents: Vec<(u64, u64)>, len: u64) -> Self {
        Self {
            inner,
            extents,
            len,
            pos: 0,
        }
    }
}

impl Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }

        let mut total = 0usize;
        let mut remaining = std::cmp::min(buf.len() as u64, self.len - self.pos);
        while remaining > 0 {
            let (extent_index, extent_offset) =
                locate_extent(&self.extents, self.pos).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "extent lookup failed")
                })?;
            let (extent_start, extent_len) = self.extents[extent_index];
            let chunk = std::cmp::min(remaining, extent_len - extent_offset);
            self.inner
                .seek(SeekFrom::Start(extent_start + extent_offset))?;
            let read = self.inner.read(&mut buf[total..total + chunk as usize])?;
            self.pos += read as u64;
            total += read;
            remaining -= read as u64;
            if read == 0 {
                break;
            }
        }

        Ok(total)
    }
}

impl Seek for FileReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(p) => (self.pos as i64 + p) as u64,
            SeekFrom::End(p) => (self.len as i64 + p) as u64,
        };
        if new_pos > self.len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek out of bounds",
            ));
        }
        self.pos = new_pos;
        Ok(self.pos)
    }
}

pub fn open_file(image_path: &Path, path: &str) -> Result<FileReader, Error> {
    let mut file = File::open(image_path)?;
    let volume = read_volume(&mut file)?;
    let mut current_icb = volume.root_icb;
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();

    for (index, part) in parts.iter().enumerate() {
        let is_last = index == parts.len() - 1;
        let dir_entry = read_file_entry(&mut file, &volume, current_icb)?;
        if dir_entry.file_type != ICBTAG_FILE_TYPE_DIRECTORY {
            return Err(Error::FileNotFound(path.to_string()));
        }

        let directory_data = read_entry_data(&mut file, &volume, &dir_entry, current_icb)?;
        let mut next = None;
        for fid in parse_directory_entries(&directory_data)? {
            if (fid.characteristics & FILE_CHARACTERISTIC_PARENT) != 0 {
                continue;
            }
            if fid.name.eq_ignore_ascii_case(part) {
                next = Some(fid.icb);
                break;
            }
        }
        let Some(found_icb) = next else {
            return Err(Error::FileNotFound(path.to_string()));
        };

        if is_last {
            let entry = read_file_entry(&mut file, &volume, found_icb)?;
            if entry.file_type != ICBTAG_FILE_TYPE_REGULAR {
                return Err(Error::Unsupported("requested path is not a regular file"));
            }
            let extents = extents_for_entry(&volume, &entry, found_icb)?;
            return Ok(FileReader::new(file.try_clone()?, extents, entry.info_len));
        }
        current_icb = found_icb;
    }

    Err(Error::FileNotFound(path.to_string()))
}

struct VolumeInfo {
    block_size: u32,
    partition: PartitionInfo,
    partition_refs: Vec<u16>,
    root_icb: LongAd,
}

fn read_volume(file: &mut File) -> Result<VolumeInfo, Error> {
    let image_len = file.metadata()?.len();
    let anchor = read_anchor(file, 256)
        .or_else(|_| read_anchor(file, image_len / SECTOR_SIZE - 256))
        .or_else(|_| read_anchor(file, image_len / SECTOR_SIZE - 1))?;

    let mut partition = None;
    let mut logical_volume = None;
    let mut sector = anchor.0;
    let sector_count = anchor.1 / SECTOR_SIZE;
    for _ in 0..sector_count {
        let offset = sector * SECTOR_SIZE;
        let mut descriptor = [0u8; SECTOR_SIZE as usize];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut descriptor)?;
        let tag_id = read_u16(&descriptor, 0)?;
        match tag_id {
            TAGID_PARTITION => {
                let number = read_u16(&descriptor, 22)?;
                let start_lba = read_u32(&descriptor, 188)?;
                partition = Some(PartitionInfo { number, start_lba });
            }
            TAGID_LOGICAL_VOLUME => {
                let block_size = read_u32(&descriptor, 212)?;
                let fsd = LongAd {
                    len: read_u32(&descriptor, 248)?,
                    lba: read_u32(&descriptor, 252)?,
                    partition: read_u16(&descriptor, 256)?,
                };
                let map_table_len = read_u32(&descriptor, 264)?;
                let map_count = read_u32(&descriptor, 268)?;
                let partition_refs = parse_partition_maps(
                    &descriptor[440..440 + map_table_len as usize],
                    map_count,
                )?;
                logical_volume = Some((block_size, fsd, partition_refs));
            }
            TAGID_TERMINATING => break,
            _ => {}
        }
        sector += 1;
    }

    let partition = partition.ok_or(Error::InvalidImage)?;
    let (block_size, fsd_ad, partition_refs) = logical_volume.ok_or(Error::InvalidImage)?;
    if !partition_refs
        .iter()
        .any(|&part_num| part_num == partition.number)
    {
        return Err(Error::Unsupported(
            "logical volume partition map does not match partition",
        ));
    }

    let fsd_sector = partition.start_lba as u64 + fsd_ad.lba as u64;
    let fsd_offset = fsd_sector * block_size as u64;
    let mut fsd = [0u8; SECTOR_SIZE as usize];
    file.seek(SeekFrom::Start(fsd_offset))?;
    file.read_exact(&mut fsd)?;
    if read_u16(&fsd, 0)? != TAGID_FILE_SET {
        return Err(Error::InvalidImage);
    }
    let root_icb = LongAd {
        len: read_u32(&fsd, 400)?,
        lba: read_u32(&fsd, 404)?,
        partition: read_u16(&fsd, 408)?,
    };

    Ok(VolumeInfo {
        block_size,
        partition,
        partition_refs,
        root_icb,
    })
}

fn read_anchor(file: &mut File, sector: u64) -> Result<(u64, u64), Error> {
    let mut buf = [0u8; SECTOR_SIZE as usize];
    file.seek(SeekFrom::Start(sector * SECTOR_SIZE))?;
    file.read_exact(&mut buf)?;
    if read_u16(&buf, 0)? != TAGID_ANCHOR {
        return Err(Error::InvalidImage);
    }
    let main_len = read_u32(&buf, 16)? as u64;
    let main_loc = read_u32(&buf, 20)? as u64;
    Ok((main_loc, main_len))
}

fn parse_partition_maps(data: &[u8], count: u32) -> Result<Vec<u16>, Error> {
    let mut offset = 0usize;
    let mut refs = Vec::new();
    for _ in 0..count {
        if offset + 2 > data.len() {
            return Err(Error::InvalidImage);
        }
        let map_type = data[offset];
        let map_len = data[offset + 1] as usize;
        if offset + map_len > data.len() || map_len < 2 {
            return Err(Error::InvalidImage);
        }
        if map_type == 1 && map_len >= 6 {
            refs.push(read_u16(data, offset + 4)?);
        }
        offset += map_len;
    }
    if refs.is_empty() {
        return Err(Error::Unsupported(
            "only type 1 partition maps are supported",
        ));
    }
    Ok(refs)
}

fn read_file_entry(
    file: &mut File,
    volume: &VolumeInfo,
    icb: LongAd,
) -> Result<FileEntryInfo, Error> {
    let offset = icb_to_offset(volume, icb)?;
    let mut block = vec![0u8; volume.block_size as usize];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut block)?;
    parse_file_entry(&block)
}

fn parse_file_entry(data: &[u8]) -> Result<FileEntryInfo, Error> {
    let tag_id = read_u16(data, 0)?;
    let (base_size, info_len_offset, ext_attr_len_offset, alloc_desc_len_offset) = match tag_id {
        TAGID_FILE_ENTRY => (176usize, 56usize, 168usize, 172usize),
        TAGID_EXTENDED_FILE_ENTRY => (216usize, 56usize, 208usize, 212usize),
        _ => return Err(Error::InvalidImage),
    };

    let flags = read_u16(data, 34)?;
    let file_type = data[27];
    let info_len = read_u64(data, info_len_offset)?;
    let ext_attr_len = read_u32(data, ext_attr_len_offset)? as usize;
    let alloc_desc_len = read_u32(data, alloc_desc_len_offset)? as usize;
    let alloc_desc_start = base_size + ext_attr_len;
    if alloc_desc_start + alloc_desc_len > data.len() {
        return Err(Error::InvalidImage);
    }

    let inline_data = if (flags & ICBTAG_FLAG_AD_MASK) == ICBTAG_FLAG_AD_IN_ICB {
        data[alloc_desc_start..alloc_desc_start + alloc_desc_len].to_vec()
    } else {
        Vec::new()
    };

    Ok(FileEntryInfo {
        file_type,
        flags,
        info_len,
        allocation_descriptors: data[alloc_desc_start..alloc_desc_start + alloc_desc_len].to_vec(),
        inline_data,
    })
}

fn read_entry_data(
    file: &mut File,
    volume: &VolumeInfo,
    entry: &FileEntryInfo,
    icb: LongAd,
) -> Result<Vec<u8>, Error> {
    if (entry.flags & ICBTAG_FLAG_AD_MASK) == ICBTAG_FLAG_AD_IN_ICB {
        return Ok(entry.inline_data.clone());
    }

    let extents = extents_for_entry(volume, entry, icb)?;
    let mut result = vec![0u8; entry.info_len as usize];
    let mut out = 0usize;
    for (offset, len) in extents {
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut result[out..out + len as usize])?;
        out += len as usize;
    }
    result.truncate(entry.info_len as usize);
    Ok(result)
}

fn extents_for_entry(
    volume: &VolumeInfo,
    entry: &FileEntryInfo,
    icb: LongAd,
) -> Result<Vec<(u64, u64)>, Error> {
    match entry.flags & ICBTAG_FLAG_AD_MASK {
        ICBTAG_FLAG_AD_IN_ICB => Ok(vec![]),
        ICBTAG_FLAG_AD_SHORT => parse_short_ad_extents(volume, &entry.allocation_descriptors),
        ICBTAG_FLAG_AD_LONG => parse_long_ad_extents(volume, &entry.allocation_descriptors),
        _ => Err(Error::Unsupported(
            "unsupported allocation descriptor format",
        )),
    }
}

fn parse_short_ad_extents(volume: &VolumeInfo, data: &[u8]) -> Result<Vec<(u64, u64)>, Error> {
    let mut extents = Vec::new();
    let mut cursor = Cursor::new(data);
    while (cursor.position() as usize) + 8 <= data.len() {
        let len = cursor.read_u32::<LittleEndian>()? & UDF_LENGTH_MASK;
        let pos = cursor.read_u32::<LittleEndian>()?;
        if len == 0 {
            continue;
        }
        let offset = (volume.partition.start_lba as u64 + pos as u64) * volume.block_size as u64;
        extents.push((offset, len as u64));
    }
    Ok(extents)
}

fn parse_long_ad_extents(volume: &VolumeInfo, data: &[u8]) -> Result<Vec<(u64, u64)>, Error> {
    let mut extents = Vec::new();
    let mut cursor = Cursor::new(data);
    while (cursor.position() as usize) + 16 <= data.len() {
        let len = cursor.read_u32::<LittleEndian>()? & UDF_LENGTH_MASK;
        let lba = cursor.read_u32::<LittleEndian>()?;
        let partition = cursor.read_u16::<LittleEndian>()?;
        let mut skip = [0u8; 6];
        cursor.read_exact(&mut skip)?;
        if len == 0 {
            continue;
        }
        let partition_number = translate_partition_ref(volume, partition)?;
        if partition_number != volume.partition.number {
            return Err(Error::Unsupported(
                "cross-partition file extents are not supported",
            ));
        }
        let offset = (volume.partition.start_lba as u64 + lba as u64) * volume.block_size as u64;
        extents.push((offset, len as u64));
    }
    Ok(extents)
}

fn parse_directory_entries(data: &[u8]) -> Result<Vec<FileIdentifier>, Error> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset + 38 <= data.len() {
        let tag_id = read_u16(data, offset)?;
        if tag_id == 0 {
            break;
        }
        if tag_id != TAGID_FILE_IDENTIFIER {
            return Err(Error::InvalidImage);
        }
        let desc_crc_len = read_u16(data, offset + 10)? as usize;
        let descriptor_len = 16 + desc_crc_len;
        if offset + descriptor_len > data.len() || descriptor_len < 38 {
            return Err(Error::InvalidImage);
        }

        let characteristics = data[offset + 18];
        let file_id_len = data[offset + 19] as usize;
        let icb = LongAd {
            len: read_u32(data, offset + 20)?,
            lba: read_u32(data, offset + 24)?,
            partition: read_u16(data, offset + 28)?,
        };
        let imp_use_len = read_u16(data, offset + 36)? as usize;
        let file_id_start = offset + 38 + imp_use_len;
        let file_id_end = file_id_start + file_id_len;
        if file_id_end > offset + descriptor_len {
            return Err(Error::InvalidImage);
        }
        let name = decode_dstring(&data[file_id_start..file_id_end])?;
        entries.push(FileIdentifier {
            name,
            icb,
            characteristics,
        });

        offset += align_up(descriptor_len, 4);
    }
    Ok(entries)
}

fn decode_dstring(data: &[u8]) -> Result<String, Error> {
    if data.is_empty() {
        return Ok(String::new());
    }
    match data[0] {
        8 => Ok(data[1..].iter().map(|&b| char::from(b)).collect()),
        16 => {
            if !(data.len() - 1).is_multiple_of(2) {
                return Err(Error::InvalidImage);
            }
            let mut units = Vec::with_capacity((data.len() - 1) / 2);
            for chunk in data[1..].chunks_exact(2) {
                units.push(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            Ok(String::from_utf16_lossy(&units))
        }
        _ => Err(Error::Unsupported("unsupported UDF string compression")),
    }
}

fn icb_to_offset(volume: &VolumeInfo, icb: LongAd) -> Result<u64, Error> {
    let partition_number = translate_partition_ref(volume, icb.partition)?;
    if partition_number != volume.partition.number {
        return Err(Error::Unsupported("cross-partition ICBs are not supported"));
    }
    Ok((volume.partition.start_lba as u64 + icb.lba as u64) * volume.block_size as u64)
}

fn translate_partition_ref(volume: &VolumeInfo, partition_ref: u16) -> Result<u16, Error> {
    if let Some(&partition_number) = volume.partition_refs.get(partition_ref as usize) {
        return Ok(partition_number);
    }
    if partition_ref == volume.partition.number {
        return Ok(partition_ref);
    }
    Err(Error::Unsupported("cross-partition ICBs are not supported"))
}

fn locate_extent(extents: &[(u64, u64)], position: u64) -> Option<(usize, u64)> {
    let mut base = 0u64;
    for (index, &(_, len)) in extents.iter().enumerate() {
        if position < base + len {
            return Some((index, position - base));
        }
        base += len;
    }
    None
}

fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, Error> {
    let end = offset + 2;
    let bytes = data.get(offset..end).ok_or(Error::InvalidImage)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset + 4;
    let bytes = data.get(offset..end).ok_or(Error::InvalidImage)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, Error> {
    let end = offset + 8;
    let bytes = data.get(offset..end).ok_or(Error::InvalidImage)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}
