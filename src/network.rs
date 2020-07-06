use crate::println;
use crate::pci;
use crate::pci::{find_device, PCIDevice};
use crate::buffer::{Packet, PACKET_SIZE, PacketWriter, PacketReader};
use crate::protocol::{TCP_FLAG_SYN, TCP_FLAG_ACK, TCP_FLAG_FIN, EtherHeader, EtherAddress, IPv4Address, IPv4Header, TCPHeader, DHCP_MSG_OFFER, DHCP_MSG_ACK, IP_PROTO_TCP, IP_PROTO_UDP, ETH_PROTOCOL_IP, ETH_PROTOCOL_ARP, ETH_PROTOCOL_ELITE, ETH_BROADCAST_ADDRESS, IP_BROADCAST_ADDRESS, ArpHeader, DHCP_CLI_PORT, DHCP_SRV_PORT, DHCPHeader, UDPHeader};
use x86_64::instructions::port::Port;
use x86_64::{
   VirtAddr,
  };
use hashbrown::HashMap;

pub const TCP_STATE_LISTEN:u8=1;
pub const TCP_STATE_SYN_SENT:u8=2;
pub const TCP_STATE_SYN_RECEIVED:u8=3;
pub const TCP_STATE_ESTABLISHED:u8=4;
pub const TCP_STATE_FIN_WAIT_1:u8=5;
pub const TCP_STATE_FIN_WAIT_2:u8=6;
pub const TCP_STATE_CLOSE_WAIT:u8=7;
pub const TCP_STATE_LAST_ACK:u8=8;
pub const TCP_STATE_TIME_WAIT:u8=9;
pub const TCP_STATE_CLOSED:u8=10;
pub const TCP_WINDOW_SIZE:u16 = 2048;
pub const HTTP_STATE_RESPONSE_SENT:u8 = 11;
pub struct TCPConnection {
    pub dst: IPv4Address,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub state: u8,
}

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
pub const REG_CAPR:u16 = 0x38;
pub const REG_CBR:u16 = 0x3a;

pub const REG_TRANSMIT_START: [u16; 4] = [0x20, 0x24, 0x28, 0x2c];
pub const REG_TRANSMIT_COMMAND: [u16; 4] = [0x10, 0x14, 0x18, 0x1c];
pub const CMD_TRANSMIT_ENABLE:u8 = 0x04;

pub const CMD_RECEIVE_ENABLE:u8 = 0x08;
pub const CMD_SW_RESET: u8 = 0x10;

pub const RTL_VENDOR_ID: u16 = 0x10ec;
pub const RTL_DEVICE_ID: u16 = 0x8139;

pub const RECEIVE_BUFFER_MAX:usize = 8 * 1024;
pub const RECEIVE_BUFFER_SIZE: usize = RECEIVE_BUFFER_MAX + 1600;
pub const TRANSMIT_BUFFER_SIZE: usize = 4;
pub const BUFFER_SIZE: usize = RECEIVE_BUFFER_SIZE + TRANSMIT_BUFFER_SIZE * PACKET_SIZE;

pub const ROK_INT_BIT: u16 = 0x1;
pub const TOK_INT_BIT: u16 = 0x4;

pub const RCR_ACCEPT_BROADCAST:u32 = 0x08;
pub const RCR_ACCEPT_MULTICAST:u32 = 0x04;
pub const RCR_ACCEPT_PHYSICAL_MATCH:u32 = 0x02;
pub const RCR_ACCEPT_ALL:u32 = 0x01;
pub const RCR_ACCEPT_ERROR:u32 = 0x10;
pub const RCR_WRAP:u32 = 1 << 7;

pub struct Network {
    adapter: PCIDevice,
    //buffer: &'static mut Buffer,
    receive_buffer_addr: u64,
    transmit_buffer_addr: u64,
    mac: EtherAddress,
    send_descriptor: usize,
    receive_ptr: usize,
    ip: IPv4Address,
    tcp_connections: HashMap<u64, TCPConnection>,
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
        println!("Configuring receive network buffer at {:#X}", self.receive_buffer_addr);
        // set the address of the receive buffer
        self.outl(REG_RBSTART, self.receive_buffer_addr as u32);
        // enable transmitter and receiver
        self.outb(REG_CMD, CMD_RECEIVE_ENABLE|CMD_TRANSMIT_ENABLE);
        // configure address masking
        self.outl(REG_RCR, RCR_WRAP|RCR_ACCEPT_BROADCAST|RCR_ACCEPT_MULTICAST|RCR_ACCEPT_PHYSICAL_MATCH|RCR_ACCEPT_ALL|RCR_ACCEPT_ERROR);
        // arm interrupts
        self.outd(REG_INTERRUPT_MASK, ROK_INT_BIT | TOK_INT_BIT);
        
        println!("Network adapter init completed.");
    }

    pub fn process_arp(&mut self, mut r: PacketReader) {
        let arp = ArpHeader::read(&mut r);
        println!("{}", arp);
    }

    pub fn process_tcp_syn(&mut self, ip: IPv4Header, tcp:TCPHeader) {
        // TODO get some sort of random number generation going here
        let sequence = 1700;
        let con = TCPConnection{seq: sequence, ack: tcp.seq + 1, state: TCP_STATE_SYN_RECEIVED, dst: ip.src, dst_port: tcp.src_port, src_port: tcp.dst_port};
        let conid = self.conid(&ip, &tcp);
        self.tcp_connections.insert(conid, con);

        let mut writer = self.get_tcp_writer(conid, TCP_FLAG_SYN | TCP_FLAG_ACK);
        let packet_length = writer.finish();
        self.transmit_packet(packet_length);
        let con = self.tcp_connections.get_mut(&conid).expect("Connection not found");
        con.seq += 1;
    }

    pub fn send_http_response(&mut self, conid: u64) {
        let mut writer = self.get_tcp_writer(conid, TCP_FLAG_ACK|TCP_FLAG_FIN);
        let data = b"HTTP/1.1 200 OK\nConnection: close\nContent-Type: text/html\n\n<html><body><h1>Hello, world!</h1>This is webOS!</body></html>";
        writer.write(data);
        let packet_length = writer.finish();
        let connection = self.tcp_connections.get_mut(&conid).expect("Connection not found after being just created");
        connection.seq += data.len() as u32;
        self.transmit_packet(packet_length);
    }

    pub fn send_tcp_flags(&mut self, conid: u64, flags:u16) {
        let mut writer = self.get_tcp_writer(conid, flags);
        let packet_length = writer.finish();
        self.transmit_packet(packet_length);
    }

    pub fn process_tcp_connection(&mut self, ip:IPv4Header, tcp: TCPHeader) {
        let conid = self.conid(&ip, &tcp);
        let tcplen = ip.len - 40;
        let con = self.tcp_connections.get_mut(&conid).expect("Connection not found");
        con.ack += tcplen as u32;
        if (tcp.flags & TCP_FLAG_ACK != 0) && con.state == TCP_STATE_SYN_RECEIVED {
            con.state = TCP_STATE_ESTABLISHED;
        } else if con.state == TCP_STATE_ESTABLISHED {
            con.state = TCP_STATE_FIN_WAIT_1;
            self.send_http_response(conid);
        } else if con.state == HTTP_STATE_RESPONSE_SENT && (tcp.flags & TCP_FLAG_ACK != 0) && tcp.ack == con.seq{
            con.state = TCP_STATE_FIN_WAIT_1;
            self.send_tcp_flags(conid, TCP_FLAG_ACK|TCP_FLAG_FIN);
        } else if tcp.flags & TCP_FLAG_FIN != 0 {
            con.state = TCP_STATE_CLOSED;
            con.ack += 1;
            self.send_tcp_flags(conid, TCP_FLAG_ACK);
            self.tcp_connections.remove(&conid);
        }
    }

    pub fn process_tcp(&mut self, ip:IPv4Header, mut r:PacketReader) {
        let tcp = TCPHeader::read(&mut r);
        #[cfg(verbose)]
        println!("{}", tcp);

        if tcp.dst_port == 80 {
            let conid = self.conid(&ip, &tcp);
            if tcp.flags & TCP_FLAG_SYN != 0 {
                self.process_tcp_syn(ip, tcp);
            }else  if self.tcp_connections.contains_key(&conid) {
                self.process_tcp_connection(ip, tcp);
            }
        }
        
    }

    pub fn process_dhcp_cli(&mut self, mut r:PacketReader) {
        let dhcp = DHCPHeader::read(&mut r);
        #[cfg(verbose)]
        println!("{}", dhcp);
        match dhcp.dhcp_type {
            DHCP_MSG_OFFER => self.send_dhcp_request(dhcp.srvaddr, dhcp.yiaddr),
            DHCP_MSG_ACK => self.handle_dhcp_finish(dhcp.yiaddr),
            _ => {},
        }
    }

    pub fn process_udp(&mut self, mut r:PacketReader) {
        let udp = UDPHeader::read(&mut r);
        #[cfg(verbose)]
        println!("{}", udp);
        if udp.dst_port == DHCP_CLI_PORT {
            self.process_dhcp_cli(r);
        }
    }
    

    pub fn process_ip(&mut self, mut r:PacketReader) {
        let ip = IPv4Header::read(&mut r);
        #[cfg(verbose)]
        println!("{}", ip);
        match ip.proto {
            IP_PROTO_TCP => self.process_tcp(ip, r),
            IP_PROTO_UDP => self.process_udp(r),
            _ => println!("Unknown ip protocol"),
        }
    }

    pub fn process_ether(&mut self, mut r: PacketReader) {
        let eth = EtherHeader::read(&mut r);
        #[cfg(verbose)]
        println!("==== PACKET ====");
        #[cfg(verbose)]
        println!("{}", eth);
        match eth.proto {
            ETH_PROTOCOL_ARP => self.process_arp(r),
            ETH_PROTOCOL_IP  => self.process_ip(r),
            _ => println!("Unknown protocol"),
        }
        
            
    }

    pub fn process_packets(&mut self) {
        let cbr = self.ind(REG_CBR);
        while cbr != self.receive_ptr as u16 {
            self.process_packet();
        }
    }
    pub fn process_packet(&mut self)  {
        let packet_buffer = self.receive_buffer_addr + (self.receive_ptr as u64);
        let packet = unsafe {
             &mut *(packet_buffer as *mut Packet)
        };
        let mut r = PacketReader::new(packet);
        let _flags = r.read_u16_le();
        let packet_length= r.read_u16_le();
        self.receive_ptr += ((packet_length +4+3)& !3) as usize;
        self.process_ether(r);
        self.update_capr();
        if self.receive_ptr > RECEIVE_BUFFER_MAX - 4 {
            self.receive_ptr -= RECEIVE_BUFFER_MAX;
        }
    }

    pub fn update_capr(&self)  {
        self.outd(REG_CAPR, self.receive_ptr as u16 - 0x10);
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
        let mut writer = self.get_ether_writer(ETH_BROADCAST_ADDRESS, ETH_PROTOCOL_ELITE);
        writer.write(msg);
        let packet_length = writer.finish();
        self.transmit_packet(packet_length);
    }

    pub fn get_writer(&self) -> PacketWriter{
        let buffer_address = self.transmit_buffer_addr as u32 + (PACKET_SIZE * self.send_descriptor) as u32;
        let buffer = unsafe { &mut *(buffer_address as *mut Packet) };
        PacketWriter::new(buffer)
    }

    pub fn get_ether_writer(&self, to: EtherAddress, proto: u16) -> PacketWriter{
        let ether = EtherHeader::new(to, self.mac, proto);
        let mut writer = self.get_writer();
        ether.write(&mut writer);
        writer
    }

    pub fn get_ip_writer(&mut self, to: IPv4Address, proto:u8) -> PacketWriter {
        let ip = self.ip;
        // TODO: arp lookup table
        let eth_to = match to {
            IP_BROADCAST_ADDRESS => ETH_BROADCAST_ADDRESS,
            _ => ETH_BROADCAST_ADDRESS,
        };
        let mut writer = self.get_ether_writer(eth_to, ETH_PROTOCOL_IP);
        let ip = IPv4Header::new(ip, to, proto);
        ip.write(&mut writer);
        writer
    }

    pub fn conid(&self, ip: &IPv4Header, tcp: &TCPHeader) -> u64 {
        (ip.src.as_u64() << 32) + ((tcp.src_port as u64) << 16) + tcp.dst_port as u64
    }
    
    pub fn get_udp_writer(&mut self, to: IPv4Address, from_port: u16, to_port: u16) -> PacketWriter {
        let mut writer = self.get_ip_writer(to, IP_PROTO_UDP);
        let udp = UDPHeader::new(from_port, to_port);
        udp.write(&mut writer);
        writer
    }

    pub fn get_tcp_writer(&mut self, conid: u64, flags: u16) -> PacketWriter {
        let connection = self.tcp_connections.get(&conid).expect("Connection not found after being just created");
        let src_port = connection.src_port;
        let dst = connection.dst;
        let dst_port = connection.dst_port;
        let seq = connection.seq;
        let ack = connection.ack;
        
        let mut writer = self.get_ip_writer(dst, IP_PROTO_TCP);
        let tcp = TCPHeader::new(src_port, dst_port, seq, ack, 5, flags, TCP_WINDOW_SIZE, 0);
        tcp.write(&mut writer);
        writer
    }

    pub fn send_dhcp_discover(&mut self) {
        let mac = self.mac;
        let mut writer = self.get_udp_writer(IP_BROADCAST_ADDRESS, DHCP_CLI_PORT, DHCP_SRV_PORT);
        let dhcp = DHCPHeader::new_discover(mac);
        dhcp.write(&mut writer);
        let packet_length = writer.finish();
        self.transmit_packet(packet_length);
    }

    
    pub fn send_dhcp_request(&mut self, server_address: IPv4Address, my_address: IPv4Address) {
        let mac = self.mac;
        let mut writer = self.get_udp_writer(IP_BROADCAST_ADDRESS, DHCP_CLI_PORT, DHCP_SRV_PORT);
        let dhcp = DHCPHeader::new_request(mac, server_address, my_address);
        dhcp.write(&mut writer);
        let packet_length = writer.finish();
        self.transmit_packet(packet_length);
    }

    fn handle_dhcp_finish(&mut self, my_address: IPv4Address) {
        self.ip = my_address;
        println!("Network configuration finished. Ready to serve on: http://{}", my_address);
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
    let transmit_buffer_addr = buffer_addr + RECEIVE_BUFFER_SIZE as u64;
    let mut network = Network{adapter: device, receive_buffer_addr: buffer_addr, transmit_buffer_addr, mac: EtherAddress::new(0), send_descriptor: 0, receive_ptr:0, ip: IPv4Address::new(0), tcp_connections:HashMap::new()};
    
    network.init_adapter();
    network
}