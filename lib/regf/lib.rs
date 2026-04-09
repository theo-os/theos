#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidHive,
    UnexpectedEof,
    UnsupportedEncoding,
}

#[derive(Debug, Clone)]
pub struct Value {
    pub ty: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Hive {
    keys: BTreeMap<String, BTreeMap<String, Value>>,
}

impl Hive {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let parser = Parser::new(bytes)?;
        let mut hive = Self::default();
        parser.walk_root(&mut hive)?;
        Ok(hive)
    }

    pub fn has_key(&self, key_path: &str) -> bool {
        self.keys.contains_key(&normalize_name(key_path))
    }

    pub fn query_value(&self, key_path: &str, value_name: &str) -> Option<&Value> {
        self.keys
            .get(&normalize_name(key_path))
            .and_then(|values| values.get(&normalize_name(value_name)))
    }

    fn insert_value(&mut self, key_path: &str, value_name: &str, value: Value) {
        let key = normalize_name(key_path);
        let name = normalize_name(value_name);
        self.keys.entry(key).or_default().insert(name, value);
    }

    fn ensure_key(&mut self, key_path: &str) {
        self.keys.entry(normalize_name(key_path)).or_default();
    }
}

fn normalize_name(name: &str) -> String {
    name.replace('/', "\\").to_ascii_lowercase()
}

struct Parser<'a> {
    bytes: &'a [u8],
    root_cell_offset: u32,
}

#[derive(Clone, Copy)]
struct NkMeta {
    flags: u16,
    subkey_count: u32,
    subkey_list_offset: u32,
    value_count: u32,
    value_list_offset: u32,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 0x1000 + 0x28 {
            return Err(Error::UnexpectedEof);
        }
        if &bytes[0..4] != b"regf" {
            return Err(Error::InvalidHive);
        }
        let root_cell_offset = read_u32(bytes, 0x24)?;
        Ok(Self {
            bytes,
            root_cell_offset,
        })
    }

    fn walk_root(&self, hive: &mut Hive) -> Result<(), Error> {
        self.walk_key(self.root_cell_offset, "", hive)
    }

    fn walk_key(&self, key_offset: u32, path: &str, hive: &mut Hive) -> Result<(), Error> {
        let (cell, _) = self.cell_payload(key_offset)?;
        if cell.len() < 0x4c || &cell[0..2] != b"nk" {
            return Err(Error::InvalidHive);
        }
        let meta = NkMeta {
            flags: read_u16(cell, 0x02)?,
            subkey_count: read_u32(cell, 0x14)?,
            subkey_list_offset: read_u32(cell, 0x1c)?,
            value_count: read_u32(cell, 0x24)?,
            value_list_offset: read_u32(cell, 0x28)?,
        };
        let name_len = read_u16(cell, 0x48)? as usize;
        let key_name = if name_len == 0 {
            String::new()
        } else {
            let name_bytes = read_bytes(cell, 0x4c, name_len)?;
            if (meta.flags & 0x20) != 0 {
                decode_ascii(name_bytes)
            } else {
                decode_utf16le(name_bytes)?
            }
        };

        let next_path = if path.is_empty() {
            key_name
        } else if key_name.is_empty() {
            path.to_string()
        } else {
            format!("{path}\\{key_name}")
        };
        hive.ensure_key(&next_path);

        self.extract_values(&meta, &next_path, hive)?;

        if meta.subkey_count == 0 || meta.subkey_list_offset == u32::MAX {
            return Ok(());
        }
        for subkey_offset in self.subkey_offsets(meta.subkey_list_offset)? {
            self.walk_key(subkey_offset, &next_path, hive)?;
        }
        Ok(())
    }

    fn extract_values(&self, meta: &NkMeta, key_path: &str, hive: &mut Hive) -> Result<(), Error> {
        if meta.value_count == 0 || meta.value_list_offset == u32::MAX {
            return Ok(());
        }
        let (list, _) = self.cell_payload(meta.value_list_offset)?;
        let count = meta.value_count as usize;
        if list.len() < count * 4 {
            return Err(Error::UnexpectedEof);
        }
        for i in 0..count {
            let value_offset = read_u32(list, i * 4)?;
            let (vk, _) = self.cell_payload(value_offset)?;
            if vk.len() < 0x18 || &vk[0..2] != b"vk" {
                continue;
            }
            let name_len = read_u16(vk, 0x02)? as usize;
            let data_len_raw = read_u32(vk, 0x04)?;
            let data_offset = read_u32(vk, 0x08)?;
            let ty = read_u32(vk, 0x0c)?;
            let flags = read_u16(vk, 0x10)?;
            let value_name = if name_len == 0 {
                String::new()
            } else {
                let bytes = read_bytes(vk, 0x18, name_len)?;
                if (flags & 0x0001) != 0 {
                    decode_ascii(bytes)
                } else {
                    decode_utf16le(bytes)?
                }
            };
            let data = self.read_value_data(data_len_raw, data_offset)?;
            hive.insert_value(key_path, &value_name, Value { ty, data });
        }
        Ok(())
    }

    fn read_value_data(&self, data_len_raw: u32, data_offset: u32) -> Result<Vec<u8>, Error> {
        let data_len = (data_len_raw & 0x7fff_ffff) as usize;
        if data_len == 0 {
            return Ok(Vec::new());
        }
        if (data_len_raw & 0x8000_0000) != 0 {
            let raw = data_offset.to_le_bytes();
            let mut out = Vec::with_capacity(data_len.min(4));
            out.extend_from_slice(&raw[..data_len.min(4)]);
            return Ok(out);
        }
        let (payload, _) = self.cell_payload(data_offset)?;
        let take = data_len.min(payload.len());
        let mut out = Vec::with_capacity(take);
        out.extend_from_slice(&payload[..take]);
        Ok(out)
    }

    fn subkey_offsets(&self, list_offset: u32) -> Result<Vec<u32>, Error> {
        let (payload, _) = self.cell_payload(list_offset)?;
        if payload.len() < 4 {
            return Err(Error::UnexpectedEof);
        }
        let sig = &payload[0..2];
        let count = read_u16(payload, 0x02)? as usize;
        match sig {
            b"li" => {
                let mut out = Vec::with_capacity(count);
                for i in 0..count {
                    out.push(read_u32(payload, 0x04 + i * 4)?);
                }
                Ok(out)
            }
            b"lf" | b"lh" => {
                let mut out = Vec::with_capacity(count);
                for i in 0..count {
                    out.push(read_u32(payload, 0x04 + i * 8)?);
                }
                Ok(out)
            }
            b"ri" => {
                let mut out = Vec::new();
                for i in 0..count {
                    let child = read_u32(payload, 0x04 + i * 4)?;
                    out.extend(self.subkey_offsets(child)?);
                }
                Ok(out)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn cell_payload(&self, rel_offset: u32) -> Result<(&'a [u8], usize), Error> {
        let abs = 0x1000usize
            .checked_add(rel_offset as usize)
            .ok_or(Error::UnexpectedEof)?;
        let cell_size_raw = read_i32(self.bytes, abs)?;
        let cell_size = cell_size_raw.unsigned_abs() as usize;
        if cell_size < 4 {
            return Err(Error::InvalidHive);
        }
        let start = abs + 4;
        let end = abs.checked_add(cell_size).ok_or(Error::UnexpectedEof)?;
        if end > self.bytes.len() || start > end {
            return Err(Error::UnexpectedEof);
        }
        Ok((&self.bytes[start..end], cell_size))
    }
}

fn read_bytes(input: &[u8], offset: usize, len: usize) -> Result<&[u8], Error> {
    let end = offset.checked_add(len).ok_or(Error::UnexpectedEof)?;
    input.get(offset..end).ok_or(Error::UnexpectedEof)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, Error> {
    let bytes = read_bytes(input, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, Error> {
    let bytes = read_bytes(input, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i32(input: &[u8], offset: usize) -> Result<i32, Error> {
    let bytes = read_bytes(input, offset, 4)?;
    Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn decode_ascii(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        out.push(char::from(b));
    }
    out
}

fn decode_utf16le(bytes: &[u8]) -> Result<String, Error> {
    if (bytes.len() % 2) != 0 {
        return Err(Error::UnsupportedEncoding);
    }
    let mut out = String::new();
    for ch in core::char::decode_utf16(
        bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
    ) {
        out.push(ch.map_err(|_| Error::UnsupportedEncoding)?);
    }
    Ok(out)
}
