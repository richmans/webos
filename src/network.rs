use crate::println;
use crate::pci;
use crate::pci::{find_device, PCIDevice};
use crate::buffer::{Packet, PACKET_SIZE, PacketWriter, PacketReader};
use crate::protocol::{EtherHeader, EtherAddress, IPv4Address, IPv4Header, TCPHeader, DHCP_MSG_OFFER, DHCP_MSG_ACK, IP_PROTO_TCP, IP_PROTO_UDP, ETH_PROTOCOL_IP, ETH_PROTOCOL_ARP, ETH_PROTOCOL_ELITE, ETH_BROADCAST_ADDRESS, IP_BROADCAST_ADDRESS, ArpHeader, DHCP_CLI_PORT, DHCP_SRV_PORT, DHCPHeader, UDPHeader};
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
pub const REG_INTERRUPT_STATUS: u16 = 0x3e;
pub const REG_RCR:u16 = 0x44;
pub const REG_MAC:u16 = 0x0;
pub const REG_TRANSMIT_START: [u16; 4] = [0x20, 0x24, 0x28, 0x2c];
pub const REG_TRANSMIT_COMMAND: [u16; 4] = [0x10, 0x14, 0x18, 0x1c];
pub const CMD_TRANSMIT_ENABLE:u8 = 0x04;

pub const CMD_RECEIVE_ENABLE:u8 = 0x08;
pub const CMD_SW_RESET: u8 = 0x10;

pub const RTL_VENDOR_ID: u16 = 0x10ec;
pub const RTL_DEVICE_ID: u16 = 0x8139;

pub const RECEIVE_BUFFER_SIZE: usize = 64 * 1024;
pub const TRANSMIT_BUFFER_SIZE: usize = 4;
pub const BUFFER_SIZE: usize = RECEIVE_BUFFER_SIZE + TRANSMIT_BUFFER_SIZE * PACKET_SIZE;

pub const ROK_INT_BIT: u16 = 0x1;
pub const TOK_INT_BIT: u16 = 0x4;

pub const RCR_ACCEPT_BROADCAST:u32 = 0x08;
pub const RCR_ACCEPT_MULTICAST:u32 = 0x04;
pub const RCR_ACCEPT_PHYSICAL_MATCH:u32 = 0x02;
pub const RCR_ACCEPT_ALL:u32 = 0x01;
pub const RCR_ACCEPT_ERROR:u32 = 0x10;

#[repr(C)]
struct Buffer {
    receive: [u8; RECEIVE_BUFFER_SIZE],
    transmit: [Packet; TRANSMIT_BUFFER_SIZE],
}

pub struct Network {
    adapter: PCIDevice,
    buffer: &'static mut Buffer,
    receive_buffer_addr: u64,
    transmit_buffer_addr: u64,
    mac: EtherAddress,
    send_descriptor: usize,
    receive_ptr: usize,
}

impl Network {
    fn init_adapter(&mut self) {
        let mac_low = self.ind(REG_MAC + 4).swap_bytes();
        let mac_high = self.inl(REG_MAC).swap_bytes();
        let mac_u64 = (mac_high as u64) << 16 | mac_low as u64;
        self.mac = EtherAddress::new(mac_u64);
        println!("Network MAC: {}", self.mac);
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
        println!("Configuring rbstart at {:#X}", self.receive_buffer_addr);
        // set the address of the receive buffer
        self.outl(REG_RBSTART, self.receive_buffer_addr as u32);
        // enable transmitter and receiver
        self.outb(REG_CMD, CMD_RECEIVE_ENABLE|CMD_TRANSMIT_ENABLE);
        // configure address masking
        self.outl(REG_RCR, RCR_ACCEPT_BROADCAST|RCR_ACCEPT_MULTICAST|RCR_ACCEPT_PHYSICAL_MATCH|RCR_ACCEPT_ALL|RCR_ACCEPT_ERROR);
        // arm interrupts
        self.outd(REG_INTERRUPT_MASK, ROK_INT_BIT | TOK_INT_BIT);
        
        println!("Network adapter init completed.");
    }


    pub fn check_packets(&self) -> bool {
        let status = self.ind(REG_INTERRUPT_STATUS);
        status & ROK_INT_BIT != 0
    }

    pub fn process_arp(&mut self, mut r: PacketReader) {
        let arp = ArpHeader::read(&mut r);
        println!("{}", arp);
    }

    pub fn process_tcp(&mut self, mut r:PacketReader) {
        let tcp = TCPHeader::read(&mut r);
        println!("{}", tcp);
    }

    pub fn process_dhcp_cli(&mut self, mut r:PacketReader) {
        let dhcp = DHCPHeader::read(&mut r);
        println!("{}", dhcp);
        match dhcp.dhcp_type {
            DHCP_MSG_OFFER => self.send_dhcp_request(dhcp.srvaddr, dhcp.yiaddr),
            DHCP_MSG_ACK => self.handle_dhcp_finish(dhcp.yiaddr),
            _ => {},
        }
    }

    pub fn process_udp(&mut self, mut r:PacketReader) {
        let udp = UDPHeader::read(&mut r);
        println!("{}", udp);
        if udp.dst_port == DHCP_CLI_PORT {
            self.process_dhcp_cli(r);
        }
    }
    

    pub fn process_ip(&mut self, mut r:PacketReader) {
        let ip = IPv4Header::read(&mut r);
        println!("{}", ip);
        match ip.proto {
            IP_PROTO_TCP => self.process_tcp(r),
            IP_PROTO_UDP => self.process_udp(r),
            _ => println!("Unknown ip protocol"),
        }
    }

    pub fn process_ether(&mut self, mut r: PacketReader) {
        let eth = EtherHeader::read(&mut r);
        println!("==== PACKET ====");
        println!("{}", eth);
        match eth.proto {
            ETH_PROTOCOL_ARP => self.process_arp(r),
            ETH_PROTOCOL_IP  => self.process_ip(r),
            _ => println!("Unknown protocol"),
        }
        
            
    }
    pub fn process_packet(&mut self)  {
        // TODO: need to account for buffer overflow -> wrap
        let packet_buffer = self.receive_buffer_addr + (self.receive_ptr as u64);
        let packet = unsafe {
             &mut *(packet_buffer as *mut Packet)
        };
        let mut r = PacketReader::new(packet);
        let _flags = r.read_u16_le();
        let packet_length= r.read_u16_le();
        //TODO: This should actually be +4, but it needs 2 more bytes, probably because of alignment
        //investigate how to properly calculate the next receive ptr.
        self.receive_ptr += (packet_length +6) as usize;
        self.process_ether(r);
    }

    pub fn interrupt_mask_port(&self) -> u16 {
        (self.adapter.bar0 as u16 & 0xfffc) + REG_INTERRUPT_MASK
    }

    pub fn interrupt_status_port(&self) -> u16 {
        (self.adapter.bar0 as u16 & 0xfffc) + REG_INTERRUPT_STATUS
    }

    pub fn disable_receive_interrupts(&self) {
        let mut mask = self.ind(REG_INTERRUPT_MASK);
        mask &= !ROK_INT_BIT;
        self.outd(REG_INTERRUPT_MASK, mask);
    }
    
    pub fn enable_receive_interrupts(&self) {
        let mut mask = self.ind(REG_INTERRUPT_MASK);
        mask |= ROK_INT_BIT;
        self.outd(REG_INTERRUPT_MASK, mask);
    }

    pub fn send_network_announcement(&mut self) {
        let msg = "Hello my friends, WebOS has joined your network!".as_bytes();
        self.send_packet(ETH_BROADCAST_ADDRESS, ETH_PROTOCOL_ELITE, msg);
    }

    pub fn send_arp_probe(&mut self) {
        // 10.0.2.15
        let my_ip = IPv4Address::new(167772687);
        // 10.0.2.2
        let target_ip =  IPv4Address::new(167772674);
        let mut writer = PacketWriter::new(&mut self.buffer.transmit[self.send_descriptor]);
        let ether_header = EtherHeader::new(ETH_BROADCAST_ADDRESS, self.mac, ETH_PROTOCOL_ARP);
        let arp_header = ArpHeader::new_request(self.mac, my_ip, target_ip);
        ether_header.write(&mut writer);
        arp_header.write(&mut writer);
        let packet_length = writer.ptr;
        self.transmit_packet(packet_length);
    }

    pub fn send_dhcp_discover(&mut self) {
        let mut writer = PacketWriter::new(&mut self.buffer.transmit[self.send_descriptor]);
        let ether = EtherHeader::new(ETH_BROADCAST_ADDRESS, self.mac, ETH_PROTOCOL_IP);
        let ipchecksum = 0x9876; // how do we know this?
        let ip = IPv4Header::new(IPv4Address::new(0), IP_BROADCAST_ADDRESS, IP_PROTO_UDP, ipchecksum);
        let udpchecksum = 0x1234; // how do we know this?
        let udp = UDPHeader::new(DHCP_CLI_PORT, DHCP_SRV_PORT, udpchecksum);
        let dhcp = DHCPHeader::new_discover(self.mac);
        ether.write(&mut writer);
        ip.write(&mut writer);
        udp.write(&mut writer);
        dhcp.write(&mut writer);
        writer.finish();
        let packet_length = writer.ptr;
        self.transmit_packet(packet_length);
    }

    pub fn send_dhcp_request(&mut self, server_address: IPv4Address, my_address: IPv4Address) {
        let mut writer = PacketWriter::new(&mut self.buffer.transmit[self.send_descriptor]);
        let ether = EtherHeader::new(ETH_BROADCAST_ADDRESS, self.mac, ETH_PROTOCOL_IP);
        let ipchecksum = 0x9876; // how do we know this?
        let ip = IPv4Header::new(IPv4Address::new(0), IP_BROADCAST_ADDRESS, IP_PROTO_UDP, ipchecksum);
        let udpchecksum = 0x1234; // how do we know this?
        let udp = UDPHeader::new(DHCP_CLI_PORT, DHCP_SRV_PORT, udpchecksum);
        let dhcp = DHCPHeader::new_request(self.mac, server_address, my_address);
        ether.write(&mut writer);
        ip.write(&mut writer);
        udp.write(&mut writer);
        dhcp.write(&mut writer);
        writer.finish();
        let packet_length = writer.ptr;
        println!("Sending dhcp request");
        self.transmit_packet(packet_length);
    }

    fn handle_dhcp_finish(&mut self, my_address: IPv4Address) {
        println!("DHCP finished. My ip: {}", my_address);
    }

    fn send_packet(&mut self, dst:EtherAddress, proto:u16, data: &[u8]) {
        let header = EtherHeader::new(dst, self.mac, proto);
        let mut writer = PacketWriter::new(&mut self.buffer.transmit[self.send_descriptor]);
        header.write(&mut writer);
        writer.write(data);
        let packet_length = writer.ptr;
        self.transmit_packet(packet_length);
    }
    
    fn transmit_packet(&mut self, packet_length:usize) {
        let buffer_address = self.transmit_buffer_addr as u32 + (PACKET_SIZE * self.send_descriptor) as u32;
        self.outl(REG_TRANSMIT_START[self.send_descriptor], buffer_address);
        self.outl(REG_TRANSMIT_COMMAND[self.send_descriptor], packet_length as u32);
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
    let mut network = Network{adapter: device, buffer, receive_buffer_addr: buffer_addr, transmit_buffer_addr, mac: EtherAddress::new(0), send_descriptor: 0, receive_ptr:0 };
    
    network.init_adapter();
    network
}