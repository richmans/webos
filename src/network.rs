use crate::println;
use crate::pci;
use crate::pci::{find_device, PCIDevice};
use x86_64::instructions::port::Port;
use x86_64::{
   VirtAddr,
  };

// registers
pub const REG_CONFIG_93C46: u16 = 0x50;
pub const REG_CONFIG_0: u16 = 0x51;
pub const REG_CONFIG_1: u16 = 0x52;

pub const REG_CMD: u16 = 0x37;
pub const REG_RBSTART: u16 = 0x30;
pub const REG_INTERRUPT_MASK: u16 = 0x3c;
pub const REG_RCR:u16 = 0x44;
pub const REG_MAC:u16 = 0x0;
pub const REG_TRANSMIT_START: [u16; 4] = [0x20, 0x24, 0x28, 0x2c];
pub const REG_TRANSMIT_COMMAND: [u16; 4] = [0x10, 0x14, 0x18, 0x1c];
pub const CMD_TRANSMIT_ENABLE:u8 = 0x04;

pub const CMD_RECEIVE_ENABLE:u8 = 0x08;
pub const CMD_SW_RESET: u8 = 0x10;

pub const RTL_VENDOR_ID: u16 = 0x10ec;
pub const RTL_DEVICE_ID: u16 = 0x8139;

pub const RECEIVE_BUFFER_SIZE: usize = 8 * 1024 + 16;
pub const TRANSMIT_BUFFER_SIZE: usize = 4 * 1792;
pub const BUFFER_SIZE: usize = RECEIVE_BUFFER_SIZE + TRANSMIT_BUFFER_SIZE;

pub const ROK_INT_BIT: u16 = 0x1;
pub const TOK_INT_BIT: u16 = 0x4;

pub const RCR_ACCEPT_BROADCAST:u32 = 0x08;
pub const RCR_ACCEPT_MULTICAST:u32 = 0x04;
pub const RCR_ACCEPT_PHYSICAL_MATCH:u32 = 0x02;
pub const RCR_ACCEPT_ADDRESS_MATCH:u32 = 0x01;

#[repr(C)]
struct Buffer {
    receive: [u8; RECEIVE_BUFFER_SIZE],
    transmit: [u8; TRANSMIT_BUFFER_SIZE],
}

pub struct Network {
    adapter: PCIDevice,
    buffer: &'static mut Buffer,
    receive_buffer_addr: u64,
    transmit_buffer_addr: u64,
    mac: u64,
    send_descriptor: usize,
}

impl Network {
    fn init_adapter(&mut self) {
        let mac_high = self.ind(REG_MAC + 4);
        let mac_low = self.inl(REG_MAC);
        self.mac = (mac_high as u64) << 32 | mac_low as u64;
        println!("Network MAC: {:X}", self.mac);
        // power on
        self.outb(REG_CONFIG_1, 0x00 as u8);
        // enable bus master bit which enables dma transfers
        self.adapter.write_register_bit(pci::REG_CMD, pci::CMD_BUS_MASTER, true);    
        // reset the adapter
        self.outb(REG_CMD, CMD_SW_RESET);
        // wait for reset to complete
        loop { 
            let status = self.inb(REG_CMD);
            if status & CMD_SW_RESET == 0 { break }
            println!("Status = 0x{:X} Waiting for reset...", status);
            for _ in 1..1000 {
                x86_64::instructions::hlt();
            }
        }
        // set the address of the receive buffer
        self.outl(REG_RBSTART, self.receive_buffer_addr as u32);
        // arm interrupts
        self.outd(REG_INTERRUPT_MASK, ROK_INT_BIT | TOK_INT_BIT);
        // configure address masking
        self.outl(REG_RCR, RCR_ACCEPT_BROADCAST|RCR_ACCEPT_MULTICAST|RCR_ACCEPT_PHYSICAL_MATCH|RCR_ACCEPT_ADDRESS_MATCH);
        // enable transmitter and receiver
        self.outb(REG_CMD, CMD_RECEIVE_ENABLE|CMD_TRANSMIT_ENABLE);
        println!("Network adapter init completed.");
        
        self.send_network_announcement(); 
    }

    fn send_network_announcement(&mut self) {
        let msg = "Hello my friends, WebOS has joined your network!".as_bytes();
        self.send_packet(0xFFFFFFFFFFFF, 0x1337, msg);
    }

    fn send_packet(&mut self, dst:u64, proto:u16, data: &[u8]) {
        // ethernet is big endian
        let mac_bytes = self.mac.to_ne_bytes();
        let dst_bytes = dst.to_ne_bytes();
        // destination mac
        for n in 0..6 { self.buffer.transmit[n] = dst_bytes[n] as u8; }
        // source mac: my own macaddress
        for n in 6..12 { self.buffer.transmit[n] = mac_bytes[n-6] as u8; }
        // protocol type ip 0x0800
        self.buffer.transmit[12] = (proto >> 8) as u8;
        self.buffer.transmit[13] = (proto & 0xFF) as u8;
        // Copy the data bytes
        for n in 0..data.len() { self.buffer.transmit[n+14] = data[n] as u8; }
        // set the current descriptor
        self.outl(REG_TRANSMIT_START[self.send_descriptor], self.transmit_buffer_addr as u32);
        self.outl(REG_TRANSMIT_COMMAND[self.send_descriptor], (14 + data.len()) as u32);
        self.send_descriptor = (self.send_descriptor + 1) % 4
    }

    #[allow(dead_code)]
    fn inb(&self, addr_offset: u16) -> u8 {
        let addr = (self.adapter.bar0 as u16 & 0xfffc)+ addr_offset;
        // println!("inb {:X}", addr);       
        unsafe{ Port::<u8>::new(addr).read() as u8}
    }
    #[allow(dead_code)]
    fn ind(&self, addr_offset: u16) -> u16 {
        let addr = (self.adapter.bar0 as u16 & 0xfffc)+ addr_offset;
        // println!("ind {:X}", addr);
        unsafe { Port::<u16>::new(addr).read() as u16}
    }
    #[allow(dead_code)]
    fn inl(&self, addr_offset: u16) -> u32 {
        let addr = (self.adapter.bar0 as u16 & 0xfffc)+ addr_offset;
        // println!("inl {:X}", addr);
        unsafe { Port::<u32>::new(addr).read() as u32 }
    }
    fn outb(&self, addr_offset: u16, data:u8) {
        let addr = (self.adapter.bar0 as u16 & 0xfffc)+ addr_offset;
        // println!("outb {:X} to {:X}", data, addr);
        unsafe { Port::new(addr).write(data) }
    }
    fn outd(&self, addr_offset: u16, data:u16) {
        let addr = (self.adapter.bar0 as u16 & 0xfffc)+ addr_offset;
        // println!("outd {:X} to {:X}", data, addr);
        unsafe { Port::new(addr).write(data) }
    }
    fn outl(&self, addr_offset: u16, data:u32) {
        let addr = (self.adapter.bar0 as u16 & 0xfffc)+ addr_offset;
        // println!("outl {:X} to {:X}", data, addr);
        unsafe { Port::new(addr).write(data) }
    }   
}

fn find_network_device() -> PCIDevice{
    // look for intel rtl8139
    match find_device(RTL_VENDOR_ID, RTL_DEVICE_ID) {
        Some(device) => {
            println!("Found network device {:?}.", device);
            device
        },
        None => panic!("No suitable network device found. Cannot continue without one."),
    }
}

pub fn init(buffer_virt_addr: VirtAddr) -> Network {
    let device = find_network_device();
    let buffer_addr = buffer_virt_addr.as_u64();
    let buffer =  unsafe { &mut *(buffer_addr as *mut Buffer) };
    let transmit_buffer_addr = buffer_addr + RECEIVE_BUFFER_SIZE as u64;
    let mut network = Network{adapter: device, buffer, receive_buffer_addr: buffer_addr, transmit_buffer_addr, mac: 0, send_descriptor: 0 };
    
    network.init_adapter();
    network
}