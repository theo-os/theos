extern crate alloc;

use crate::allocator;
use crate::pci::{self, PciAddress, PciDevice};
use core::mem::size_of;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};
use crabfs::device::BlockDevice;
use crabfs::error::DeviceError;
use x86_64::VirtAddr;
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};

const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_DEVICE_ID_BLOCK_MODERN: u16 = 0x1042;
const VIRTIO_DEVICE_ID_BLOCK_TRANSITIONAL: u16 = 0x1001;

const VIRTIO_PCI_CAP_VENDOR: u8 = 0x09;
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
const VIRTIO_STATUS_FAILED: u8 = 0x80;

const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;

const QUEUE_SIZE: u16 = 8;
const REQUEST_TIMEOUT_SPINS: usize = 5_000_000;
const SECTOR_SIZE: usize = 512;

const VQ_DESC_VADDR: u64 = 0x6666_0000_0000;
const VQ_AVAIL_VADDR: u64 = 0x6666_0000_1000;
const VQ_USED_VADDR: u64 = 0x6666_0000_2000;
const VQ_REQ_VADDR: u64 = 0x6666_0000_3000;

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioPciCap {
    cap_vndr: u8,
    cap_next: u8,
    cap_len: u8,
    cfg_type: u8,
    bar: u8,
    id: u8,
    padding: [u8; 2],
    offset: u32,
    length: u32,
}

#[repr(C)]
struct VirtioPciCommonCfg {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc: u64,
    queue_driver: u64,
    queue_device: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct VirtqAvail<const N: usize> {
    flags: u16,
    idx: u16,
    ring: [u16; N],
    used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
struct VirtqUsed<const N: usize> {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; N],
    avail_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioBlkReqHeader {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioBlkError {
    DeviceNotFound,
    BadCapabilities,
    MissingCapability,
    MmioMap,
    VirtqueueSetup,
    FeatureNegotiation,
    RequestFailed,
    Timeout,
    OutOfRange,
}

#[derive(Debug, Clone, Copy)]
struct DmaRegion {
    virt: VirtAddr,
    phys: u64,
}

fn alloc_dma_page(vaddr: u64) -> Result<DmaRegion, VirtioBlkError> {
    let virt = VirtAddr::new(vaddr);
    let page = Page::<Size4KiB>::containing_address(virt);
    let frame =
        allocator::allocate_and_map_page(page, PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
            .map_err(|_| VirtioBlkError::VirtqueueSetup)?;
    allocator::zero_page(page);
    Ok(DmaRegion {
        virt,
        phys: frame.start_address().as_u64(),
    })
}

#[derive(Debug)]
struct VirtQueue {
    desc: DmaRegion,
    avail: DmaRegion,
    used: DmaRegion,
    req: DmaRegion,
    last_used_idx: u16,
}

impl VirtQueue {
    fn new() -> Result<Self, VirtioBlkError> {
        Ok(Self {
            desc: alloc_dma_page(VQ_DESC_VADDR)?,
            avail: alloc_dma_page(VQ_AVAIL_VADDR)?,
            used: alloc_dma_page(VQ_USED_VADDR)?,
            req: alloc_dma_page(VQ_REQ_VADDR)?,
            last_used_idx: 0,
        })
    }

    unsafe fn desc_mut(&self) -> &mut [VirtqDesc; QUEUE_SIZE as usize] {
        unsafe {
            &mut *(self
                .desc
                .virt
                .as_mut_ptr::<[VirtqDesc; QUEUE_SIZE as usize]>())
        }
    }

    unsafe fn avail_mut(&self) -> &mut VirtqAvail<{ QUEUE_SIZE as usize }> {
        unsafe {
            &mut *(self
                .avail
                .virt
                .as_mut_ptr::<VirtqAvail<{ QUEUE_SIZE as usize }>>())
        }
    }

    unsafe fn used_ref(&self) -> &VirtqUsed<{ QUEUE_SIZE as usize }> {
        unsafe {
            &*(self
                .used
                .virt
                .as_ptr::<VirtqUsed<{ QUEUE_SIZE as usize }>>())
        }
    }
}

pub struct VirtioBlkDevice {
    common_cfg: *mut VirtioPciCommonCfg,
    notify_ptr: *mut u16,
    isr_ptr: *mut u8,
    capacity_sectors: u64,
    queue: VirtQueue,
}

unsafe impl Send for VirtioBlkDevice {}

impl VirtioBlkDevice {
    pub fn probe() -> Result<Self, VirtioBlkError> {
        let devices = pci::scan_devices();
        let mut blk_dev: Option<PciDevice> = None;
        for dev in devices {
            if dev.vendor_id == VIRTIO_VENDOR_ID
                && (dev.device_id == VIRTIO_DEVICE_ID_BLOCK_MODERN
                    || dev.device_id == VIRTIO_DEVICE_ID_BLOCK_TRANSITIONAL)
            {
                blk_dev = Some(dev);
                break;
            }
        }
        let dev = blk_dev.ok_or(VirtioBlkError::DeviceNotFound)?;
        let caps = pci::capabilities(dev.address);

        let mut common_cfg = core::ptr::null_mut::<VirtioPciCommonCfg>();
        let mut notify_base = core::ptr::null_mut::<u8>();
        let mut notify_mult = 0u32;
        let mut isr_ptr = core::ptr::null_mut::<u8>();
        let mut device_cfg = core::ptr::null_mut::<u8>();

        for cap in caps.into_iter().flatten() {
            if cap.id != VIRTIO_PCI_CAP_VENDOR {
                continue;
            }
            let raw = read_cap(dev.address, cap.offset);
            let bar = dev
                .bars
                .get(raw.bar as usize)
                .and_then(|b| *b)
                .ok_or(VirtioBlkError::BadCapabilities)?;
            if !bar.is_mmio {
                continue;
            }
            let mmio = pci::map_mmio(bar.address + u64::from(raw.offset), u64::from(raw.length))
                .map_err(|_| VirtioBlkError::MmioMap)?;

            match raw.cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => common_cfg = mmio.as_mut_ptr(),
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    notify_base = mmio.as_mut_ptr();
                    notify_mult = pci::read_config_dword(dev.address, cap.offset + 16);
                }
                VIRTIO_PCI_CAP_ISR_CFG => isr_ptr = mmio.as_mut_ptr(),
                VIRTIO_PCI_CAP_DEVICE_CFG => device_cfg = mmio.as_mut_ptr(),
                _ => {}
            }
        }

        if common_cfg.is_null()
            || notify_base.is_null()
            || isr_ptr.is_null()
            || device_cfg.is_null()
        {
            return Err(VirtioBlkError::MissingCapability);
        }

        let mut out = Self {
            common_cfg,
            notify_ptr: core::ptr::null_mut(),
            isr_ptr,
            capacity_sectors: 0,
            queue: VirtQueue::new()?,
        };

        out.init_device(notify_base, notify_mult, device_cfg)?;
        Ok(out)
    }

    fn init_device(
        &mut self,
        notify_base: *mut u8,
        notify_mult: u32,
        device_cfg: *mut u8,
    ) -> Result<(), VirtioBlkError> {
        self.set_status(0);
        self.set_status(VIRTIO_STATUS_ACKNOWLEDGE);
        self.set_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

        let features = self.device_features();
        if (features & VIRTIO_F_VERSION_1) == 0 {
            self.fail();
            return Err(VirtioBlkError::FeatureNegotiation);
        }
        self.set_driver_features(VIRTIO_F_VERSION_1);
        self.set_status(self.get_status() | VIRTIO_STATUS_FEATURES_OK);
        if (self.get_status() & VIRTIO_STATUS_FEATURES_OK) == 0 {
            self.fail();
            return Err(VirtioBlkError::FeatureNegotiation);
        }

        self.setup_queue0(notify_base, notify_mult)?;

        // Read block capacity from device config.
        self.capacity_sectors = unsafe { read_volatile(device_cfg.cast::<u64>()) };

        self.set_status(self.get_status() | VIRTIO_STATUS_DRIVER_OK);
        Ok(())
    }

    fn setup_queue0(
        &mut self,
        notify_base: *mut u8,
        notify_mult: u32,
    ) -> Result<(), VirtioBlkError> {
        let cfg = unsafe { &mut *self.common_cfg };
        unsafe {
            write_volatile(&mut cfg.queue_select, 0);
        }
        let queue_size = unsafe { read_volatile(&cfg.queue_size) };
        if queue_size == 0 || queue_size < QUEUE_SIZE {
            return Err(VirtioBlkError::VirtqueueSetup);
        }
        unsafe {
            write_volatile(&mut cfg.queue_size, QUEUE_SIZE);
            write_volatile(&mut cfg.queue_desc, self.queue.desc.phys);
            write_volatile(&mut cfg.queue_driver, self.queue.avail.phys);
            write_volatile(&mut cfg.queue_device, self.queue.used.phys);
            write_volatile(&mut cfg.queue_enable, 1);
        }
        let notify_off = unsafe { read_volatile(&cfg.queue_notify_off) };
        let notify_addr = notify_base as usize + usize::from(notify_off) * notify_mult as usize;
        self.notify_ptr = notify_addr as *mut u16;
        Ok(())
    }

    fn device_features(&self) -> u64 {
        let cfg = unsafe { &mut *self.common_cfg };
        unsafe {
            write_volatile(&mut cfg.device_feature_select, 0);
            let lo = u64::from(read_volatile(&cfg.device_feature));
            write_volatile(&mut cfg.device_feature_select, 1);
            let hi = u64::from(read_volatile(&cfg.device_feature));
            (hi << 32) | lo
        }
    }

    fn set_driver_features(&self, features: u64) {
        let cfg = unsafe { &mut *self.common_cfg };
        unsafe {
            write_volatile(&mut cfg.driver_feature_select, 0);
            write_volatile(&mut cfg.driver_feature, (features & 0xffff_ffff) as u32);
            write_volatile(&mut cfg.driver_feature_select, 1);
            write_volatile(&mut cfg.driver_feature, (features >> 32) as u32);
        }
    }

    fn get_status(&self) -> u8 {
        unsafe { read_volatile(&(*self.common_cfg).device_status) }
    }

    fn set_status(&self, status: u8) {
        unsafe {
            write_volatile(&mut (*self.common_cfg).device_status, status);
        }
    }

    fn fail(&self) {
        self.set_status(self.get_status() | VIRTIO_STATUS_FAILED);
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors.saturating_mul(SECTOR_SIZE as u64)
    }

    fn submit_rw(
        &mut self,
        req_type: u32,
        sector: u64,
        data: &mut [u8],
    ) -> Result<(), VirtioBlkError> {
        if data.len() != SECTOR_SIZE {
            return Err(VirtioBlkError::RequestFailed);
        }

        let header_offset = 0usize;
        let data_offset = 64usize;
        let status_offset = data_offset + SECTOR_SIZE;
        let req_ptr = self.queue.req.virt.as_mut_ptr::<u8>();
        unsafe {
            let hdr = &mut *(req_ptr.add(header_offset) as *mut VirtioBlkReqHeader);
            *hdr = VirtioBlkReqHeader {
                req_type,
                reserved: 0,
                sector,
            };

            if req_type == VIRTIO_BLK_T_OUT {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    req_ptr.add(data_offset),
                    SECTOR_SIZE,
                );
            }
            *req_ptr.add(status_offset) = 0xff;

            let desc = self.queue.desc_mut();
            desc[0] = VirtqDesc {
                addr: self.queue.req.phys + header_offset as u64,
                len: size_of::<VirtioBlkReqHeader>() as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            };
            let data_flags = if req_type == VIRTIO_BLK_T_IN {
                VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
            } else {
                VIRTQ_DESC_F_NEXT
            };
            desc[1] = VirtqDesc {
                addr: self.queue.req.phys + data_offset as u64,
                len: SECTOR_SIZE as u32,
                flags: data_flags,
                next: 2,
            };
            desc[2] = VirtqDesc {
                addr: self.queue.req.phys + status_offset as u64,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };

            let avail = self.queue.avail_mut();
            let slot = (avail.idx % QUEUE_SIZE) as usize;
            avail.ring[slot] = 0;
            fence(Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);
            fence(Ordering::SeqCst);
            write_volatile(self.notify_ptr, 0);
        }

        let mut spins = 0usize;
        loop {
            let used_idx = unsafe { self.queue.used_ref().idx };
            if used_idx != self.queue.last_used_idx {
                self.queue.last_used_idx = used_idx;
                break;
            }
            spins += 1;
            if spins > REQUEST_TIMEOUT_SPINS {
                return Err(VirtioBlkError::Timeout);
            }
            core::hint::spin_loop();
        }

        let _isr = unsafe { read_volatile(self.isr_ptr) };
        let status = unsafe { *req_ptr.add(status_offset) };
        if status != 0 {
            return Err(VirtioBlkError::RequestFailed);
        }
        if req_type == VIRTIO_BLK_T_IN {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    req_ptr.add(data_offset),
                    data.as_mut_ptr(),
                    SECTOR_SIZE,
                );
            }
        }
        Ok(())
    }

    fn read_sector(
        &mut self,
        sector: u64,
        out: &mut [u8; SECTOR_SIZE],
    ) -> Result<(), VirtioBlkError> {
        if sector >= self.capacity_sectors {
            return Err(VirtioBlkError::OutOfRange);
        }
        self.submit_rw(VIRTIO_BLK_T_IN, sector, out)
    }

    fn write_sector(
        &mut self,
        sector: u64,
        data: &mut [u8; SECTOR_SIZE],
    ) -> Result<(), VirtioBlkError> {
        if sector >= self.capacity_sectors {
            return Err(VirtioBlkError::OutOfRange);
        }
        self.submit_rw(VIRTIO_BLK_T_OUT, sector, data)
    }
}

impl BlockDevice for VirtioBlkDevice {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), DeviceError> {
        let end = offset.saturating_add(buf.len() as u64);
        if end > self.capacity_bytes() {
            return Err(DeviceError::OutOfRange);
        }
        if buf.is_empty() {
            return Ok(());
        }

        let mut remaining = buf.len();
        let mut out_pos = 0usize;
        let mut cur_off = offset;
        while remaining > 0 {
            let sector = cur_off / SECTOR_SIZE as u64;
            let in_sector = (cur_off % SECTOR_SIZE as u64) as usize;
            let take = remaining.min(SECTOR_SIZE - in_sector);
            let mut tmp = [0u8; SECTOR_SIZE];
            self.read_sector(sector, &mut tmp)
                .map_err(|_| DeviceError::Io)?;
            buf[out_pos..out_pos + take].copy_from_slice(&tmp[in_sector..in_sector + take]);

            cur_off += take as u64;
            out_pos += take;
            remaining -= take;
        }
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), DeviceError> {
        let end = offset.saturating_add(buf.len() as u64);
        if end > self.capacity_bytes() {
            return Err(DeviceError::OutOfRange);
        }
        if buf.is_empty() {
            return Ok(());
        }

        let mut remaining = buf.len();
        let mut in_pos = 0usize;
        let mut cur_off = offset;
        while remaining > 0 {
            let sector = cur_off / SECTOR_SIZE as u64;
            let in_sector = (cur_off % SECTOR_SIZE as u64) as usize;
            let take = remaining.min(SECTOR_SIZE - in_sector);
            let mut tmp = [0u8; SECTOR_SIZE];

            if take != SECTOR_SIZE {
                self.read_sector(sector, &mut tmp)
                    .map_err(|_| DeviceError::Io)?;
            }
            tmp[in_sector..in_sector + take].copy_from_slice(&buf[in_pos..in_pos + take]);
            self.write_sector(sector, &mut tmp)
                .map_err(|_| DeviceError::Io)?;

            cur_off += take as u64;
            in_pos += take;
            remaining -= take;
        }
        Ok(())
    }
}

fn read_cap(addr: PciAddress, cap_offset: u8) -> VirtioPciCap {
    let mut bytes = [0u8; size_of::<VirtioPciCap>()];
    let mut i = 0usize;
    while i < bytes.len() {
        bytes[i] = pci::read_config_byte(addr, cap_offset + i as u8);
        i += 1;
    }
    unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<VirtioPciCap>()) }
}
