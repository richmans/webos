#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]
use webos::task::Task;
use webos::task::executor::Executor; // new

use webos::task::keyboard; 
use webos::task::network; 
use core::panic::PanicInfo;
use webos::println;
#[cfg(test)]
use webos::test_runner;
use webos::Kernel;
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
pub fn dothings(kernel:Kernel)  {
    let mut executor = Executor::new(); // new
    executor.spawn(Task::new(keyboard::print_keypresses()));
    executor.spawn(Task::new(network::process_packets(kernel.network_buffer)));
    executor.run();
}


#[allow(unconditional_panic)]
pub fn main(boot_info: &'static BootInfo) -> ! {
    println!("WebOS Initializing");
    let kernel = webos::init(boot_info);
    dothings(kernel);
    println!("WebOS is ready to serve.");   
    webos::hlt_loop();  
}
