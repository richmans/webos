use bootloader::bootinfo::MemoryMap;
use bootloader::bootinfo::MemoryRegionType;
use x86_64::{
  structures::paging::{
      mapper::MapToError, FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB,
      PageTable, PhysFrame, OffsetPageTable,
  },
  PhysAddr,
  VirtAddr,
};

/// Initialize a new OffsetPageTable.
///
/// This function is unsafe because the caller must guarantee that the
/// complete physical memory is mapped to virtual memory at the passed
/// `physical_memory_offset`. Also, this function must be only called once
/// to avoid aliasing `&mut` references (which is undefined behavior).
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = active_level_4_table(physical_memory_offset);
    OffsetPageTable::new(level_4_table, physical_memory_offset)
}

/// Returns a mutable reference to the active level 4 table.
///
/// This function is unsafe because the caller must guarantee that the
/// complete physical memory is mapped to virtual memory at the passed
/// `physical_memory_offset`. Also, this function must be only called once
/// to avoid aliasing `&mut` references (which is undefined behavior).
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr)
  -> &'static mut PageTable
{
  use x86_64::registers::control::Cr3;

  let (level_4_table_frame, _) = Cr3::read();

  let phys = level_4_table_frame.start_address();
  let virt = physical_memory_offset + phys.as_u64();
  let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

  &mut *page_table_ptr // unsafe
}

/// A FrameAllocator that returns usable frames from the bootloader's memory map.
pub struct BootInfoFrameAllocator {
    memory_map: &'static MemoryMap,
    next: usize,
}

impl BootInfoFrameAllocator {
    /// Create a FrameAllocator from the passed memory map.
    ///
    /// This function is unsafe because the caller must guarantee that the passed
    /// memory map is valid. The main requirement is that all frames that are marked
    /// as `USABLE` in it are really unused.
    pub unsafe fn init(memory_map: &'static MemoryMap) -> Self {
        BootInfoFrameAllocator {
            memory_map,
            next: 0,
        }
    }

    /// Returns an iterator over the usable frames specified in the memory map.
    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
      // get usable regions from memory map
      let regions = self.memory_map.iter();
      let usable_regions = regions
          .filter(|r| r.region_type == MemoryRegionType::Usable);
      // map each region to its address range
      let addr_ranges = usable_regions
          .map(|r| r.range.start_addr()..r.range.end_addr());
      // transform to an iterator of frame start addresses
      let frame_addresses = addr_ranges.flat_map(|r| r.step_by(4096));
      // create `PhysFrame` types from the start addresses
      frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
  }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
  fn allocate_frame(&mut self) -> Option<PhysFrame> {
      let frame = self.usable_frames().nth(self.next);
      self.next += 1;
      frame
  }
}

pub fn allocate_identity_mapped(
  size:usize,
  mapper: &mut impl Mapper<Size4KiB>,
  frame_allocator: &mut impl FrameAllocator<Size4KiB>) ->
  Result<VirtAddr, MapToError<Size4KiB>> {
  
  let first_frame = frame_allocator
      .allocate_frame()
      .ok_or(MapToError::FrameAllocationFailed)?;  
  let start_addr = first_frame.start_address().as_u64();
  let end_addr = start_addr + size as u64;
  let mut addr = start_addr;
  while addr < end_addr {
    let virt_address = VirtAddr::new(addr);
    let page = Page::containing_address(virt_address);
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let frame = unsafe {
      PhysFrame::from_start_address_unchecked(PhysAddr::new(addr))
    };
    unsafe {
      mapper.map_to(page, frame, flags, frame_allocator)?.flush();
    };
    addr += 4096u64;
    let next_frame = frame_allocator
      .allocate_frame()
      .ok_or(MapToError::FrameAllocationFailed)?;
    let allocated_addr= next_frame.start_address().as_u64();
    if allocated_addr != addr {
      panic!("Invalid identity page mapping. Reserved frame was expected to be {:X} but got {:X}", addr, allocated_addr);
    }
    
  }
  let virt_result = VirtAddr::new(start_addr);
  Ok(virt_result)
}

pub fn allocate_block(
  start:usize, 
  size: usize,
  mapper: &mut impl Mapper<Size4KiB>,
  frame_allocator: &mut impl FrameAllocator<Size4KiB>) ->
  Result<(), MapToError<Size4KiB>> {
  let page_range = {
    let block_start = VirtAddr::new(start as u64);
    let block_end = VirtAddr::new((start as u64) + (size as u64) - 1u64);
    let block_start_page = Page::containing_address(block_start);
    let block_end_page = Page::containing_address(block_end);
    Page::range_inclusive(block_start_page, block_end_page)
  };

  for page in page_range {
      let frame = frame_allocator
          .allocate_frame()
          .ok_or(MapToError::FrameAllocationFailed)?;
      let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
      unsafe {
          mapper.map_to(page, frame, flags, frame_allocator)?.flush()
      };
  }
  Ok(())
}