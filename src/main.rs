#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use webos::println;
use webos::serial_println;
#[cfg(test)]
use webos::test_runner;


#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    webos::test_panic_handler(info)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    #[cfg(test)]
    {
        test_main();
        loop {}
    }

    #[cfg(not(test))]
    main();
    
}

pub fn dothings()  {
    
}
#[allow(unconditional_panic)]
pub fn main() -> ! {
    serial_println!("WebOS Initializing");
    println!("WebOS Initializing");
    webos::init();
   
    
    dothings();
    serial_println!("WebOS Did not crash");
    println!("WebOS Did not crash");
    
    loop {
         
    }
}
