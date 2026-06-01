extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use lz4_flex::block::{compress, decompress};

pub const PAGE_SIZE: usize = 4096;

const SIZE_CLASSES: [usize; 14] = [
    64, 96, 128, 160, 192, 256, 320, 512, 768, 1024, 1536, 2048, 3072, 4096,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZsHandle {
    class_index: usize,
    page_index: usize,
    slot_index: usize,
    generation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZramEncoding {
    Raw,
    Lz4,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ZsStats {
    pub zspages: usize,
    pub used_slots: usize,
    pub capacity_bytes: usize,
    pub stored_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ZramStats {
    pub stores: u64,
    pub loads: u64,
    pub invalidations: u64,
    pub compressed_pages: usize,
    pub raw_pages: usize,
    pub logical_bytes: usize,
    pub stored_bytes: usize,
    pub allocator: ZsStats,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ZswapStats {
    pub hits: u64,
    pub misses: u64,
    pub backend: ZramStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZramError {
    PageIndexOutOfRange,
    PageTooLarge,
    ObjectTooLarge,
    InvalidHandle,
    MissingPage,
    DecompressionFailed,
}

#[derive(Debug)]
struct ZsPage {
    slot_size: usize,
    pages_per_zspage: usize,
    storage: Vec<u8>,
    slot_lengths: Vec<usize>,
    slot_generations: Vec<u32>,
    free_list: Vec<usize>,
    used_slots: usize,
}

impl ZsPage {
    fn new(slot_size: usize, pages_per_zspage: usize) -> Self {
        let bytes = PAGE_SIZE * pages_per_zspage;
        let slots = (bytes / slot_size).max(1);
        Self {
            slot_size,
            pages_per_zspage,
            storage: vec![0; bytes],
            slot_lengths: vec![0; slots],
            slot_generations: vec![0; slots],
            free_list: (0..slots).rev().collect(),
            used_slots: 0,
        }
    }

    fn allocate(&mut self, bytes: &[u8]) -> Option<(usize, u32)> {
        if bytes.len() > self.slot_size {
            return None;
        }

        let slot = self.free_list.pop()?;
        let generation = nonzero_generation(self.slot_generations[slot].wrapping_add(1));
        self.slot_generations[slot] = generation;
        self.slot_lengths[slot] = bytes.len();
        self.used_slots += 1;

        let offset = slot * self.slot_size;
        self.storage[offset..offset + bytes.len()].copy_from_slice(bytes);
        Some((slot, generation))
    }

    fn read(&self, slot: usize, generation: u32) -> Result<Vec<u8>, ZramError> {
        if slot >= self.slot_lengths.len()
            || self.slot_generations[slot] != generation
            || self.slot_lengths[slot] == 0
        {
            return Err(ZramError::InvalidHandle);
        }

        let offset = slot * self.slot_size;
        let len = self.slot_lengths[slot];
        Ok(self.storage[offset..offset + len].to_vec())
    }

    fn free(&mut self, slot: usize, generation: u32) -> Result<(), ZramError> {
        if slot >= self.slot_lengths.len()
            || self.slot_generations[slot] != generation
            || self.slot_lengths[slot] == 0
        {
            return Err(ZramError::InvalidHandle);
        }

        self.slot_lengths[slot] = 0;
        self.slot_generations[slot] =
            nonzero_generation(self.slot_generations[slot].wrapping_add(1));
        self.free_list.push(slot);
        self.used_slots = self.used_slots.saturating_sub(1);
        Ok(())
    }

    fn used_bytes(&self) -> usize {
        self.slot_lengths.iter().sum()
    }

    fn capacity_bytes(&self) -> usize {
        self.pages_per_zspage * PAGE_SIZE
    }
}

#[derive(Debug)]
struct SizeClassPool {
    slot_size: usize,
    pages_per_zspage: usize,
    zspages: Vec<ZsPage>,
}

impl SizeClassPool {
    fn new(slot_size: usize) -> Self {
        Self {
            slot_size,
            pages_per_zspage: pages_per_zspage(slot_size),
            zspages: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct ZsAllocator {
    classes: Vec<SizeClassPool>,
}

impl ZsAllocator {
    pub fn new() -> Self {
        Self {
            classes: SIZE_CLASSES
                .iter()
                .copied()
                .map(SizeClassPool::new)
                .collect(),
        }
    }

    pub fn store(&mut self, bytes: &[u8]) -> Result<ZsHandle, ZramError> {
        let class_index = size_class_index(bytes.len()).ok_or(ZramError::ObjectTooLarge)?;
        let pool = &mut self.classes[class_index];

        for (page_index, page) in pool.zspages.iter_mut().enumerate() {
            if let Some((slot_index, generation)) = page.allocate(bytes) {
                return Ok(ZsHandle {
                    class_index,
                    page_index,
                    slot_index,
                    generation,
                });
            }
        }

        let mut page = ZsPage::new(pool.slot_size, pool.pages_per_zspage);
        let (slot_index, generation) = page.allocate(bytes).ok_or(ZramError::ObjectTooLarge)?;
        pool.zspages.push(page);

        Ok(ZsHandle {
            class_index,
            page_index: pool.zspages.len() - 1,
            slot_index,
            generation,
        })
    }

    pub fn load(&self, handle: ZsHandle) -> Result<Vec<u8>, ZramError> {
        let page = self
            .classes
            .get(handle.class_index)
            .and_then(|pool| pool.zspages.get(handle.page_index))
            .ok_or(ZramError::InvalidHandle)?;
        page.read(handle.slot_index, handle.generation)
    }

    pub fn free(&mut self, handle: ZsHandle) -> Result<(), ZramError> {
        let page = self
            .classes
            .get_mut(handle.class_index)
            .and_then(|pool| pool.zspages.get_mut(handle.page_index))
            .ok_or(ZramError::InvalidHandle)?;
        page.free(handle.slot_index, handle.generation)
    }

    pub fn stats(&self) -> ZsStats {
        let mut stats = ZsStats::default();
        for pool in &self.classes {
            for page in &pool.zspages {
                stats.zspages += 1;
                stats.used_slots += page.used_slots;
                stats.capacity_bytes += page.capacity_bytes();
                stats.stored_bytes += page.used_bytes();
            }
        }
        stats
    }
}

#[derive(Debug, Clone, Copy)]
struct ZramEntry {
    handle: ZsHandle,
    original_len: usize,
    stored_len: usize,
    encoding: ZramEncoding,
}

#[derive(Debug)]
pub struct ZramDevice {
    max_pages: usize,
    allocator: ZsAllocator,
    pages: BTreeMap<usize, ZramEntry>,
    stores: u64,
    loads: u64,
    invalidations: u64,
}

impl ZramDevice {
    pub fn new(max_pages: usize) -> Self {
        Self {
            max_pages,
            allocator: ZsAllocator::new(),
            pages: BTreeMap::new(),
            stores: 0,
            loads: 0,
            invalidations: 0,
        }
    }

    pub fn store_page(&mut self, page_index: usize, page: &[u8]) -> Result<(), ZramError> {
        if page_index >= self.max_pages {
            return Err(ZramError::PageIndexOutOfRange);
        }
        if page.len() > PAGE_SIZE {
            return Err(ZramError::PageTooLarge);
        }

        let compressed = compress(page);
        let (encoding, payload) = if compressed.len() < page.len() && compressed.len() <= PAGE_SIZE
        {
            (ZramEncoding::Lz4, compressed)
        } else {
            (ZramEncoding::Raw, page.to_vec())
        };

        let handle = self.allocator.store(&payload)?;
        let replaced = self.pages.insert(
            page_index,
            ZramEntry {
                handle,
                original_len: page.len(),
                stored_len: payload.len(),
                encoding,
            },
        );
        if let Some(old_entry) = replaced {
            let _ = self.allocator.free(old_entry.handle);
        }

        self.stores = self.stores.saturating_add(1);
        Ok(())
    }

    pub fn load_page(&mut self, page_index: usize) -> Result<Vec<u8>, ZramError> {
        let entry = *self.pages.get(&page_index).ok_or(ZramError::MissingPage)?;
        let payload = self.allocator.load(entry.handle)?;
        self.loads = self.loads.saturating_add(1);

        match entry.encoding {
            ZramEncoding::Raw => Ok(payload),
            ZramEncoding::Lz4 => {
                decompress(&payload, entry.original_len).map_err(|_| ZramError::DecompressionFailed)
            }
        }
    }

    pub fn invalidate_page(&mut self, page_index: usize) -> Result<(), ZramError> {
        if let Some(entry) = self.pages.remove(&page_index) {
            self.invalidations = self.invalidations.saturating_add(1);
            self.allocator.free(entry.handle)?;
        }
        Ok(())
    }

    pub fn stats(&self) -> ZramStats {
        let mut stats = ZramStats {
            stores: self.stores,
            loads: self.loads,
            invalidations: self.invalidations,
            allocator: self.allocator.stats(),
            ..ZramStats::default()
        };

        for entry in self.pages.values() {
            stats.logical_bytes += entry.original_len;
            stats.stored_bytes += entry.stored_len;
            match entry.encoding {
                ZramEncoding::Raw => stats.raw_pages += 1,
                ZramEncoding::Lz4 => stats.compressed_pages += 1,
            }
        }

        stats
    }
}

#[derive(Debug)]
pub struct ZswapCache {
    backend: ZramDevice,
    hits: u64,
    misses: u64,
}

impl ZswapCache {
    pub fn new(max_slots: usize) -> Self {
        Self {
            backend: ZramDevice::new(max_slots),
            hits: 0,
            misses: 0,
        }
    }

    pub fn store(&mut self, swap_slot: usize, page: &[u8]) -> Result<(), ZramError> {
        self.backend.store_page(swap_slot, page)
    }

    pub fn load(&mut self, swap_slot: usize) -> Result<Vec<u8>, ZramError> {
        match self.backend.load_page(swap_slot) {
            Ok(page) => {
                self.hits = self.hits.saturating_add(1);
                Ok(page)
            }
            Err(err) => {
                self.misses = self.misses.saturating_add(1);
                Err(err)
            }
        }
    }

    pub fn invalidate(&mut self, swap_slot: usize) -> Result<(), ZramError> {
        self.backend.invalidate_page(swap_slot)
    }

    pub fn stats(&self) -> ZswapStats {
        ZswapStats {
            hits: self.hits,
            misses: self.misses,
            backend: self.backend.stats(),
        }
    }
}

fn size_class_index(size: usize) -> Option<usize> {
    SIZE_CLASSES.iter().position(|class| *class >= size)
}

fn pages_per_zspage(slot_size: usize) -> usize {
    if slot_size <= 512 {
        1
    } else if slot_size <= 2048 {
        2
    } else {
        4
    }
}

fn nonzero_generation(generation: u32) -> u32 {
    if generation == 0 { 1 } else { generation }
}
