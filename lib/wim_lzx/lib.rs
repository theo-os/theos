#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use thiserror::Error;

const MAIN_CODE_COUNT: usize = 496;
const MAIN_CODE_SPLIT: usize = 256;
const LEN_CODE_COUNT: usize = 249;
const LEN_SHIFT: u16 = 9;
const CODE_MASK: u16 = 0x01ff;
const TABLE_BITS: u8 = 9;
const TABLE_SIZE: usize = 1 << TABLE_BITS;
const MAX_BLOCK_SIZE: usize = 32 * 1024;
const WINDOW_SIZE: usize = 32 * 1024;
const MAX_TREE_PATH_LEN: u8 = 16;
const E8_FILE_SIZE: i32 = 12_000_000;
const MAX_E8_OFFSET: i64 = 0x3fff_ffff;

const VERBATIM_BLOCK: u16 = 1;
const ALIGNED_OFFSET_BLOCK: u16 = 2;
const UNCOMPRESSED_BLOCK: u16 = 3;

const FOOTER_BITS: [u8; 31] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
    11, 11, 12, 12, 13, 13, 14,
];

const BASE_POSITION: [u16; 31] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512,
    768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768,
];

#[derive(Debug, Error)]
pub enum Error {
    #[error("WIM LZX data is corrupt")]
    Corrupt,
    #[error("unexpected end of WIM LZX input at {context} (byte_offset={byte_offset}, bit_count={bit_count}, block_start={block_start}, block_type={block_type}, block_size={block_size})")]
    UnexpectedEof {
        context: &'static str,
        byte_offset: usize,
        bit_count: u8,
        block_start: usize,
        block_type: u16,
        block_size: usize,
    },
    #[error("uncompressed chunk size {0} exceeds 32768 bytes")]
    ChunkTooLarge(usize),
}

#[derive(Clone)]
struct Huffman {
    extra: Vec<Vec<u16>>,
    maxbits: u8,
    table: [u16; TABLE_SIZE],
}

fn build_table(codelens: &[u8]) -> Option<Huffman> {
    let mut count = [0usize; MAX_TREE_PATH_LEN as usize + 1];
    let mut max = 0u8;
    for &cl in codelens {
        if cl > MAX_TREE_PATH_LEN {
            return None;
        }
        count[cl as usize] += 1;
        max = max.max(cl);
    }

    if max == 0 {
        return Some(Huffman {
            extra: Vec::new(),
            maxbits: 0,
            table: [0; TABLE_SIZE],
        });
    }

    let mut first = [0usize; MAX_TREE_PATH_LEN as usize + 1];
    let mut code = 0usize;
    for i in 1..=max as usize {
        code <<= 1;
        first[i] = code;
        code += count[i];
    }

    if code != 1usize << max {
        return None;
    }

    let mut h = Huffman {
        extra: Vec::new(),
        maxbits: max,
        table: [0; TABLE_SIZE],
    };

    if max > TABLE_BITS {
        let core = first[TABLE_BITS as usize + 1] / 2;
        let nextra = (1usize << TABLE_BITS) - core;
        h.extra = (0..nextra)
            .map(|_| vec![0; 1usize << (max - TABLE_BITS)])
            .collect();
        for code in core..(1usize << TABLE_BITS) {
            h.table[code] = (code - core) as u16;
        }
    }

    for (i, &cl) in codelens.iter().enumerate() {
        if cl == 0 {
            continue;
        }
        let code = first[cl as usize];
        first[cl as usize] += 1;
        let value = ((cl as u16) << LEN_SHIFT) | i as u16;
        if cl <= TABLE_BITS {
            let extended = code << (TABLE_BITS - cl);
            for j in 0..(1usize << (TABLE_BITS - cl)) {
                h.table[extended + j] = value;
            }
        } else {
            let prefix = code >> (cl - TABLE_BITS) as usize;
            let suffix_mask = (1usize << (cl - TABLE_BITS)) - 1;
            let suffix = code & suffix_mask;
            let extended = suffix << (max - cl);
            let extra_index = h.table[prefix] as usize;
            for j in 0..(1usize << (max - cl)) {
                h.extra[extra_index][extended + j] = value;
            }
        }
    }

    Some(h)
}

struct Decoder<'a> {
    input: &'a [u8],
    byte_offset: usize,
    bit_count: u8,
    bit_buffer: u32,
    unaligned: bool,
    lru: [u16; 3],
    mainlens: [u8; MAIN_CODE_COUNT],
    lenlens: [u8; LEN_CODE_COUNT],
    window: [u8; WINDOW_SIZE],
    current_block_start: usize,
    current_block_type: u16,
    current_block_size: usize,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            byte_offset: 0,
            bit_count: 0,
            bit_buffer: 0,
            unaligned: false,
            lru: [1, 1, 1],
            mainlens: [0; MAIN_CODE_COUNT],
            lenlens: [0; LEN_CODE_COUNT],
            window: [0; WINDOW_SIZE],
            current_block_start: 0,
            current_block_type: 0,
            current_block_size: 0,
        }
    }

    fn unexpected_eof(&self, context: &'static str) -> Error {
        Error::UnexpectedEof {
            context,
            byte_offset: self.byte_offset,
            bit_count: self.bit_count,
            block_start: self.current_block_start,
            block_type: self.current_block_type,
            block_size: self.current_block_size,
        }
    }

    fn ensure_at_least(&self, bytes: usize) -> Result<(), Error> {
        if self.input.len().saturating_sub(self.byte_offset) < bytes {
            Err(self.unexpected_eof("input buffer"))
        } else {
            Ok(())
        }
    }

    fn try_feed(&mut self) -> bool {
        if self.input.len().saturating_sub(self.byte_offset) < 2 {
            return false;
        }
        let lo = self.input[self.byte_offset] as u32;
        let hi = self.input[self.byte_offset + 1] as u32;
        self.bit_buffer |= ((hi << 8) | lo) << (16 - self.bit_count);
        self.bit_count += 16;
        self.byte_offset += 2;
        true
    }

    fn get_bits(&mut self, n: u8) -> Result<u16, Error> {
        if n == 0 {
            return Ok(0);
        }
        if self.bit_count < n {
            if !self.try_feed() {
                return Err(self.unexpected_eof("get_bits"));
            }
        }
        let value = (self.bit_buffer >> (32 - n)) as u16;
        self.bit_buffer <<= n;
        self.bit_count -= n;
        Ok(value)
    }

    fn get_code(&mut self, h: &Huffman) -> Result<u16, Error> {
        if h.maxbits == 0 {
            return Err(Error::Corrupt);
        }
        if self.bit_count < MAX_TREE_PATH_LEN {
            let _ = self.try_feed();
        }

        let mut code = h.table[(self.bit_buffer >> (32 - TABLE_BITS)) as usize];
        if code < (1 << LEN_SHIFT) {
            if h.maxbits <= TABLE_BITS {
                return Err(Error::Corrupt);
            }
            let extra = code as usize;
            let suffix_shift = 32 - (h.maxbits - TABLE_BITS) as u32;
            let suffix = (self.bit_buffer << TABLE_BITS >> suffix_shift) as usize;
            code = h.extra[extra][suffix];
        }

        let n = (code >> LEN_SHIFT) as u8;
        if self.bit_count < n {
            return Err(self.unexpected_eof("huffman code tail"));
        }
        self.bit_buffer <<= n;
        self.bit_count -= n;
        Ok(code & CODE_MASK)
    }

    fn read_tree(&mut self, lens: &mut [u8]) -> Result<(), Error> {
        let mut pretree_len = [0u8; 20];
        for elem in &mut pretree_len {
            *elem = self.get_bits(4)? as u8;
        }
        let pretree = build_table(&pretree_len).ok_or(Error::Corrupt)?;

        let mut i = 0usize;
        while i < lens.len() {
            let c = self.get_code(&pretree)? as u8;
            match c {
                0..=16 => {
                    lens[i] = (lens[i] + 17 - c) % 17;
                    i += 1;
                }
                17 => {
                    let zeroes = self.get_bits(4)? as usize + 4;
                    if i + zeroes > lens.len() {
                        return Err(Error::Corrupt);
                    }
                    lens[i..i + zeroes].fill(0);
                    i += zeroes;
                }
                18 => {
                    let zeroes = self.get_bits(5)? as usize + 20;
                    if i + zeroes > lens.len() {
                        return Err(Error::Corrupt);
                    }
                    lens[i..i + zeroes].fill(0);
                    i += zeroes;
                }
                19 => {
                    let same = self.get_bits(1)? as usize + 4;
                    if i + same > lens.len() {
                        return Err(Error::Corrupt);
                    }
                    let delta = self.get_code(&pretree)? as u8;
                    if delta > 16 {
                        return Err(Error::Corrupt);
                    }
                    let length = (lens[i] + 17 - delta) % 17;
                    lens[i..i + same].fill(length);
                    i += same;
                }
                _ => return Err(Error::Corrupt),
            }
        }

        Ok(())
    }

    fn read_block_header(&mut self) -> Result<(u16, u16), Error> {
        if self.unaligned {
            self.ensure_at_least(1)?;
            self.byte_offset += 1;
            self.unaligned = false;
        }

        let block_type = self.get_bits(3)?;
        let full = self.get_bits(1)?;
        let block_size = if full != 0 {
            MAX_BLOCK_SIZE as u16
        } else {
            let size = self.get_bits(16)?;
            if size as usize > MAX_BLOCK_SIZE {
                return Err(Error::Corrupt);
            }
            size
        };

        match block_type {
            VERBATIM_BLOCK | ALIGNED_OFFSET_BLOCK => {}
            UNCOMPRESSED_BLOCK => {
                let n = if self.bit_count == 0 { 16 } else { self.bit_count };
                self.get_bits(n)?;
                self.ensure_at_least(12)?;
                self.lru[0] = u32::from_le_bytes(
                    self.input[self.byte_offset..self.byte_offset + 4]
                        .try_into()
                        .expect("slice length checked"),
                ) as u16;
                self.lru[1] = u32::from_le_bytes(
                    self.input[self.byte_offset + 4..self.byte_offset + 8]
                        .try_into()
                        .expect("slice length checked"),
                ) as u16;
                self.lru[2] = u32::from_le_bytes(
                    self.input[self.byte_offset + 8..self.byte_offset + 12]
                        .try_into()
                        .expect("slice length checked"),
                ) as u16;
                self.byte_offset += 12;
            }
            _ => return Err(Error::Corrupt),
        }

        Ok((block_type, block_size))
    }

    fn read_trees(&mut self, read_aligned: bool) -> Result<(Huffman, Huffman, Option<Huffman>), Error> {
        let aligned = if read_aligned {
            let mut aligned_len = [0u8; 8];
            for elem in &mut aligned_len {
                *elem = self.get_bits(3)? as u8;
            }
            Some(build_table(&aligned_len).ok_or(Error::Corrupt)?)
        } else {
            None
        };

        let mut main_prefix = self.mainlens[..MAIN_CODE_SPLIT].to_vec();
        self.read_tree(&mut main_prefix)?;
        self.mainlens[..MAIN_CODE_SPLIT].copy_from_slice(&main_prefix);

        let mut main_suffix = self.mainlens[MAIN_CODE_SPLIT..].to_vec();
        self.read_tree(&mut main_suffix)?;
        self.mainlens[MAIN_CODE_SPLIT..].copy_from_slice(&main_suffix);

        let main = build_table(&self.mainlens).ok_or(Error::Corrupt)?;

        let mut len_lens = self.lenlens.to_vec();
        self.read_tree(&mut len_lens)?;
        self.lenlens.copy_from_slice(&len_lens);

        let length = build_table(&self.lenlens).ok_or(Error::Corrupt)?;
        Ok((main, length, aligned))
    }

    fn read_compressed_block(
        &mut self,
        start: usize,
        end: usize,
        hmain: &Huffman,
        hlength: &Huffman,
        haligned: Option<&Huffman>,
    ) -> Result<usize, Error> {
        let mut i = start;
        while i < end {
            let main = self.get_code(hmain)?;
            if main < 256 {
                self.window[i] = main as u8;
                i += 1;
                continue;
            }

            let mut matchlen = (main - 256) % 8;
            let slot = ((main - 256) / 8) as usize;
            if slot >= FOOTER_BITS.len() {
                return Err(Error::Corrupt);
            }
            if matchlen == 7 {
                matchlen += self.get_code(hlength)?;
            }
            matchlen += 2;

            let matchoffset = if slot < 3 {
                let offset = self.lru[slot];
                self.lru[slot] = self.lru[0];
                self.lru[0] = offset;
                offset
            } else {
                let offset_bits = FOOTER_BITS[slot];
                let (verbatim_bits, aligned_bits) = if offset_bits > 0 {
                    if let Some(aligned) = haligned {
                        if offset_bits >= 3 {
                            (self.get_bits(offset_bits - 3)? * 8, self.get_code(aligned)?)
                        } else {
                            (self.get_bits(offset_bits)?, 0)
                        }
                    } else {
                        (self.get_bits(offset_bits)?, 0)
                    }
                } else {
                    (0, 0)
                };

                let offset = BASE_POSITION[slot]
                    .wrapping_add(verbatim_bits)
                    .wrapping_add(aligned_bits)
                    .wrapping_sub(2);
                self.lru[2] = self.lru[1];
                self.lru[1] = self.lru[0];
                self.lru[0] = offset;
                offset
            } as usize;

            if matchoffset == 0 || matchoffset > i || i + matchlen as usize > end {
                return Err(Error::Corrupt);
            }

            let copy_end = i + matchlen as usize;
            while i < copy_end {
                self.window[i] = self.window[i - matchoffset];
                i += 1;
            }
        }

        Ok(i - start)
    }

    fn read_block(&mut self, start: usize) -> Result<usize, Error> {
        let (block_type, size) = self.read_block_header()?;
        let size = size as usize;
        self.current_block_start = start;
        self.current_block_type = block_type;
        self.current_block_size = size;

        if block_type == UNCOMPRESSED_BLOCK {
            if size % 2 == 1 {
                self.unaligned = true;
            }

            let available = self.input.len().saturating_sub(self.byte_offset);
            if available < size {
                return Err(Error::UnexpectedEof {
                    context: "uncompressed block payload",
                    byte_offset: self.byte_offset,
                    bit_count: self.bit_count,
                    block_start: self.current_block_start,
                    block_type: self.current_block_type,
                    block_size: self.current_block_size,
                });
            }
            self.window[start..start + size]
                .copy_from_slice(&self.input[self.byte_offset..self.byte_offset + size]);
            self.byte_offset += size;
            return Ok(size);
        }

        let (hmain, hlength, haligned) = self.read_trees(block_type == ALIGNED_OFFSET_BLOCK)?;
        self.read_compressed_block(start, start + size, &hmain, &hlength, haligned.as_ref())
    }
}

fn decode_e8(buffer: &mut [u8], offset: i64) {
    if offset > MAX_E8_OFFSET || buffer.len() < 10 {
        return;
    }

    let mut i = 0usize;
    while i + 10 <= buffer.len() {
        if buffer[i] == 0xe8 {
            let current_ptr = offset as i32 + i as i32;
            let absolute = i32::from_le_bytes([
                buffer[i + 1],
                buffer[i + 2],
                buffer[i + 3],
                buffer[i + 4],
            ]);
            if absolute >= -current_ptr && absolute < E8_FILE_SIZE {
                let relative = if absolute >= 0 {
                    absolute - current_ptr
                } else {
                    absolute + E8_FILE_SIZE
                };
                buffer[i + 1..i + 5].copy_from_slice(&relative.to_le_bytes());
            }
            i += 5;
        } else {
            i += 1;
        }
    }
}

pub fn decompress(chunk: &[u8], uncompressed_size: usize) -> Result<Vec<u8>, Error> {
    if uncompressed_size > WINDOW_SIZE {
        return Err(Error::ChunkTooLarge(uncompressed_size));
    }

    let mut decoder = Decoder::new(chunk);
    let mut written = 0usize;
    while written < uncompressed_size {
        written += decoder.read_block(written)?;
    }

    let mut output = decoder.window[..uncompressed_size].to_vec();
    decode_e8(&mut output, 0);
    Ok(output)
}

impl fmt::Display for Huffman {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "huffman(maxbits={})", self.maxbits)
    }
}
