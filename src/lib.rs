#![feature(abi_x86_interrupt)] 
#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]
#![feature(alloc_error_handler)]

extern crate alloc;
pub mod memory;
pub mod allocator;
pub mod serial;
pub mod vga_buffer;
pub mod interrupts;
pub mod gdt;
pub mod pci;
pub mod network;
use core::panic::PanicInfo;
#[cfg(test)]
use bootloader::entry_point;
use bootloader::BootInfo;
use x86_64::VirtAddr;


#[cfg(test)]
entry_point!(test_kernel_main);

// verifies that a certain buffer is identity mapped.
fn memory_test(membuf: VirtAddr, phys_mem_offset:VirtAddr, bufsize: usize) {
    println!("Testing memory mapping");
    let phys_offset = phys_mem_offset.as_u64();
    let offset = membuf.as_u64();
    for n in 0..bufsize as u64 {
        let mapped_buffer =  unsafe { &mut *((offset + n) as *mut u8) };
        let phys_buffer =  unsafe { &mut *((offset + n + phys_offset) as *mut u8) };
        *mapped_buffer = 0x41;
        if *phys_buffer != 0x41 {
            panic!("Memory mapping test FAILED");
        }
        
    }
    println!("Memory mapping test done");
}
pub fn init(boot_info: &'static BootInfo) {
    gdt::init();
    interrupts::init_idt();
    pci::scan();
    unsafe { interrupts::PICS.lock().initialize() }; 
    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = unsafe { memory::init(phys_mem_offset) };
    let mut frame_allocator = unsafe {
        memory::BootInfoFrameAllocator::init(&boot_info.memory_map)
    };
    let network_buffer = memory::allocate_identity_mapped(network::BUFFER_SIZE, &mut mapper, &mut frame_allocator).expect("Network buffer allocation failed.");
    allocator::init_heap(&mut mapper, &mut frame_allocator)
        .expect("heap initialization failed");
  
    memory_test(network_buffer, phys_mem_offset, network::BUFFER_SIZE);
    x86_64::instructions::interrupts::enable();  
    network::init(network_buffer);
}

pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

pub fn test_runner(tests: &[&dyn Fn()]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    exit_qemu(QemuExitCode::Success);
}

pub fn test_panic_handler(info: &PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
    hlt_loop();   
}

#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("allocation error: {:?}", layout)
}

/// Entry point for `cargo xtest`
#[cfg(test)]
#[no_mangle]
fn test_kernel_main(boot_info: &'static BootInfo) -> ! {
    init();
    test_main();
    hlt_loop();   
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) {
    use x86_64::instructions::port::Port;

    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }
}
