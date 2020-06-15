use linked_list_allocator::LockedHeap;
use crate::memory;

use x86_64::{
  structures::paging::{
      mapper::MapToError, FrameAllocator, Mapper, Size4KiB,      
  },
};

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 1024 * 1024; // 1MB

pub fn init_heap(
  mapper: &mut impl Mapper<Size4KiB>,
  frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
  let result = memory::allocate_block(HEAP_START, HEAP_SIZE, mapper, frame_allocator);
  match result {
    Ok(()) => {},
    error => return error,
  }
  unsafe {
    ALLOCATOR.lock().init(HEAP_START, HEAP_SIZE);
  }
  Ok(())
}