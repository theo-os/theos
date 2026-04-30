use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::fmt;

const SECTOR_SIZE: u64 = 2048;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidImage,
    FileNotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::InvalidImage => f.write_str("not a valid ISO 9660 image"),
            Self::FileNotFound(path) => write!(f, "path not found in ISO image: {path}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct FileReader {
    inner: File,
    start: u64,
    len: u64,
    pos: u64,
}

impl FileReader {
    fn new(inner: File, start: u64, len: u64) -> Self {
        Self {
            inner,
            start,
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
        let to_read = std::cmp::min(buf.len() as u64, self.len - self.pos) as usize;
        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let read = self.inner.read(&mut buf[..to_read])?;
        self.pos += read as u64;
        Ok(read)
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

struct DirectoryRecord {
    extent_location: u32,
    extent_length: u32,
    name: String,
}

pub fn open_file(iso_path: &Path, path: &str) -> Result<FileReader, Error> {
    let mut file = File::open(iso_path)?;
    let (mut current_dir_extent, mut current_dir_length) = read_root_directory(&mut file)?;

    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    for (index, part) in parts.iter().enumerate() {
        let is_last = index == parts.len() - 1;
        let mut found = None;
        for record in read_directory(&mut file, current_dir_extent, current_dir_length)? {
            if record.name.eq_ignore_ascii_case(part) {
                found = Some(record);
                break;
            }
        }
        let Some(record) = found else {
            return Err(Error::FileNotFound(path.to_string()));
        };
        if is_last {
            return Ok(FileReader::new(
                file.try_clone()?,
                record.extent_location as u64 * SECTOR_SIZE,
                record.extent_length as u64,
            ));
        }
        current_dir_extent = record.extent_location;
        current_dir_length = record.extent_length;
    }

    Err(Error::FileNotFound(path.to_string()))
}

fn read_root_directory(file: &mut File) -> Result<(u32, u32), Error> {
    file.seek(SeekFrom::Start(16 * SECTOR_SIZE))?;
    let volume_type = file.read_u8()?;
    let mut id = [0u8; 5];
    file.read_exact(&mut id)?;
    if volume_type != 1 || &id != b"CD001" {
        return Err(Error::InvalidImage);
    }
    file.seek(SeekFrom::Current(149))?;
    let record = read_directory_record(file)?;
    Ok((record.extent_location, record.extent_length))
}

fn read_directory(
    file: &mut File,
    extent_location: u32,
    extent_length: u32,
) -> Result<Vec<DirectoryRecord>, Error> {
    let start = extent_location as u64 * SECTOR_SIZE;
    let end = start + extent_length as u64;
    let mut pos = start;
    let mut records = Vec::new();
    while pos < end {
        file.seek(SeekFrom::Start(pos))?;
        let record_len = file.read_u8()?;
        if record_len == 0 {
            pos = ((pos / SECTOR_SIZE) + 1) * SECTOR_SIZE;
            continue;
        }
        file.seek(SeekFrom::Start(pos))?;
        records.push(read_directory_record(file)?);
        pos += u64::from(record_len);
    }
    Ok(records)
}

fn read_directory_record(file: &mut File) -> Result<DirectoryRecord, Error> {
    let length = file.read_u8()?;
    let _ext_attr_length = file.read_u8()?;
    let extent_location = file.read_u32::<LittleEndian>()?;
    file.seek(SeekFrom::Current(4))?;
    let extent_length = file.read_u32::<LittleEndian>()?;
    file.seek(SeekFrom::Current(4 + 7 + 1 + 1 + 1))?;
    let _volume_sequence_number = file.read_u16::<LittleEndian>()?;
    file.seek(SeekFrom::Current(2))?;
    let file_id_length = file.read_u8()?;
    let mut file_id = vec![0u8; file_id_length as usize];
    file.read_exact(&mut file_id)?;

    let name = if file_id == [0] {
        ".".to_string()
    } else if file_id == [1] {
        "..".to_string()
    } else {
        let mut name = String::from_utf8_lossy(&file_id).to_string();
        if let Some(version_sep) = name.find(';') {
            name.truncate(version_sep);
        }
        name
    };

    let consumed = 33u8.saturating_add(file_id_length);
    if length > consumed {
        file.seek(SeekFrom::Current((length - consumed) as i64))?;
    }

    Ok(DirectoryRecord {
        extent_location,
        extent_length,
        name,
    })
}
