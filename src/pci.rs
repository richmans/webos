use crate::println;

pub const REG_CMD: u8 = 0x4;
pub const CMD_BUS_MASTER: u8 = 2;
pub const REG_BAR0: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PCIDevice {
    bus: u8,
    slot: u8,
    function: u8,
    vendor: u16,
    deviceid: u16,
    class_code: u8,
    sub_class: u8,
    pub bar0: u32,
}

impl PCIDevice {
    pub fn sequence(&self) -> u16 {
        (self.bus as u16 * 256 + self.slot as u16 * 8 + self.function as u16) as u16
    }

    pub fn read_byte_register(&self, offset:u8) -> u8 {
        read_config_byte(self.bus, self.slot, self.function, offset)
    }

    pub fn read_long_register(&self, offset:u8) -> u32 {
        read_config_long(self.bus, self.slot, self.function, offset)
    }

    pub fn read_register(&self, offset:u8) -> u16 {
        read_config_word(self.bus, self.slot, self.function, offset)
    }

    pub fn write_byte_register(&self, offset:u8, data: u8) {
        write_config_byte(self.bus, self.slot, self.function, offset, data)
    }
    pub fn write_register(&self, offset:u8, data: u16) {
        write_config_word(self.bus, self.slot, self.function, offset, data)
    }

    pub fn write_long_register(&self, offset:u8, data: u32) {
        write_long_config_word(self.bus, self.slot, self.function, offset, data)
    }

    pub fn write_register_bit(&self, offset:u8, bit:u8, enable:bool) {
        let val = self.read_register(offset);
        let new_val:u16;
        if enable {
            new_val = val | (1<<bit);
        } else {
            new_val = val & (1 << bit);
        } 
        self.write_register(offset, new_val);  
    }
}


pub fn calculate_config_address(bus:u8, slot:u8, func:u8, offset:u8) -> u32 {
    let mut address:u32 = 0;
    address |= bus as u32;
    address <<= 5;
    address |= (slot & 0x1F) as u32;
    address <<= 3;
    address |= (func & 0x7) as u32;
    address <<= 8;
    address |= (offset & 0xFF) as u32;
    address |= 0x80000000 as u32;
    address as u32
}

fn  arm_address(bus:u8, slot:u8, func:u8, offset:u8) {
    use x86_64::instructions::port::Port;
    let address:u32 = calculate_config_address(bus, slot, func, offset);
    unsafe {
        let mut port = Port::new(0xCF8);
        port.write(address as u32);
    }
}

pub fn read_config_byte(bus:u8, slot:u8, func:u8, offset:u8) -> u8{
    use x86_64::instructions::port::Port;
    arm_address(bus, slot, func, offset);
    unsafe {
        let mut port = Port::new(0xCFC);
        port.read()
    }
}

pub fn read_config_word(bus:u8, slot:u8, func:u8, offset:u8) -> u16{
    use x86_64::instructions::port::Port;
    arm_address(bus, slot, func, offset);
    unsafe {
        let mut port = Port::new(0xCFC);
        port.read()
    }
}

pub fn read_config_long(bus:u8, slot:u8, func:u8, offset:u8) -> u32{
    use x86_64::instructions::port::Port;
    arm_address(bus, slot, func, offset);
    unsafe {
        let mut port = Port::new(0xCFC);
        port.read()
    }
}
pub fn write_long_config_word(bus:u8, slot:u8, func:u8, offset:u8, data:u32) {
    use x86_64::instructions::port::Port;
    arm_address(bus, slot, func, offset);
    unsafe {
        let mut port = Port::new(0xCFC);
        port.write(data);
    }
   
}
pub fn write_config_word(bus:u8, slot:u8, func:u8, offset:u8, data:u16) {
    use x86_64::instructions::port::Port;
    arm_address(bus, slot, func, offset);
    unsafe {
        let mut port = Port::new(0xCFC);
        port.write(data);
    }
}

pub fn write_config_byte(bus:u8, slot:u8, func:u8, offset:u8, data:u8) {
    use x86_64::instructions::port::Port;
    arm_address(bus, slot, func, offset);
    unsafe {
        let mut port = Port::new(0xCFC);
        port.write(data);
    }
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
    let bar0 = read_config_long(bus, slot, function, REG_BAR0);
    let device = PCIDevice{bus, slot, function, vendor, deviceid, class_code, sub_class, bar0};    
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