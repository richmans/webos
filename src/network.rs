use crate::println;
use crate::pci::{find_device, scan};

pub fn find_network_device() {
    scan();

    // look for intel 83540em
    let deviceid: u16 = 0x100e;
    let vendorid: u16 = 0x8086;
    match find_device(vendorid, deviceid) {
        Some(device) => println!("Found network device {:?}.", device),
        None => println!("No suitable network device found."),
    }
}