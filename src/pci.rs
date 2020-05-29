use crate::println;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PCIDevice {
    bus: u8,
    slot: u8,
    function: u8,
    vendor: u16,
    deviceid: u16,
    class_code: u8,
    sub_class: u8
}

impl PCIDevice {
    pub fn sequence(&self) -> u16 {
        (self.bus as u16 * 256 + self.slot as u16 * 8 + self.function as u16) as u16
    }
}


pub fn read_config_word(bus:u8, slot:u8, func:u8, offset:u8) -> u16{
    use x86_64::instructions::port::Port;
    let mut address:u32 = 0;
    address |= bus as u32;
    address <<= 5;
    address |= (slot & 0x1F) as u32;
    address <<= 3;
    address |= (func & 0x7) as u32;
    address <<= 8;
    address |= (offset & 0xFF) as u32;
    address |= 0x80000000 as u32;
    let result:u32;
    unsafe {
        let mut port = Port::new(0xCF8);
        port.write(address as u32);
        port = Port::new(0xCFC);
        result = port.read();
    }
    result as u16
}

pub fn read_device(seq: u16) -> Option<PCIDevice> {
    let bus = (seq >> 8) as u8;
    let slot = ((seq >>3) & 0x1f) as u8;
    let function = (seq & 0x7) as u8;
    let vendor = read_config_word(bus, slot, function, 0);
    if vendor == 0xffff as u16 {
        return None;
    }
    let deviceid = read_config_word(bus, slot, function, 2);
    let class_data = read_config_word(bus, slot, function, 10);
    let class_code = (class_data >> 8) as u8;
    let sub_class = (class_data & 0xFF) as u8;
    let device = PCIDevice{bus, slot, function, vendor, deviceid, class_code, sub_class};    
    Some(device)
}

pub fn scan() {
    println!("Scanning PCI");
    for device in devices() {
        println!("Found device {:?}:{}:{} is Vendor:{:X} Deviceid:{:X} Class:{:X} Subclass:{:X}",device.bus, device.slot, device.function, device.vendor, device.deviceid, device.class_code, device.sub_class);
    }
}

pub fn find_device(vendorid:u16, deviceid:u16) -> Option<PCIDevice> {
    for device in devices() {
        if device.deviceid == deviceid && device.vendor == vendorid {
            return Some(device);
        }
    }
    None
}

pub fn devices() -> PCIIterator {
    PCIIterator{sequence: 0}
}

pub struct PCIIterator {
    sequence: u32,
}

impl Iterator for PCIIterator {
    type Item = PCIDevice;
    fn next(&mut self) -> Option<PCIDevice> {
        while self.sequence < 256*32*8 {
            match read_device(self.sequence as u16){
                None => {
                    if self.sequence % 8 == 0 {
                        self.sequence += 8;
                    } else {
                        self.sequence += 1;
                    }
                },
                Some(device) => {self.sequence +=1; return Some(device) }, 
            }
        }
        None
    }
}