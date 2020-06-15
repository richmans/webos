#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use webos::println;
#[cfg(test)]
use webos::test_runner;
extern crate alloc;
use bootloader::{BootInfo, entry_point};

entry_point!(kernel_main);

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    webos::hlt_loop(); 
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    webos::test_panic_handler(info)
}

#[no_mangle]
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    #[cfg(test)]
    {
        test_main();
        loop {}
    }

    #[cfg(not(test))]
    main(boot_info);   
}

// this function runs after everything is initialized
// i use this for doodles that are later converted to tests.
pub fn dothings()  {
    
}

#[allow(unconditional_panic)]
pub fn main(boot_info: &'static BootInfo) -> ! {
    println!("WebOS Initializing");
    webos::init(boot_info);
    dothings();
    println!("WebOS is ready to serve.");   
    webos::hlt_loop();  
}
