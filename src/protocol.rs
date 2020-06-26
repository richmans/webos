use crate::buffer::{PacketWriter, PacketReader};
use core;
use alloc::vec::Vec;

// this is a very lazy implementation parsers and builders for the following protocols:
// * ethernet II
// * IPv4
// * UDP
// * TCP
// * DHCP
// it is lazy because 
// * i have disabled all optional fields (like udp crc) 
// * i don't parse any fields that i don't need right now
// * generators only for the package types that i really need (like dhcp discover, but not offer)



#[derive(Debug, Copy, Clone)]
pub struct EtherAddress(u64);

impl EtherAddress {
  pub fn new(addr:u64) -> EtherAddress {
    EtherAddress(addr)
  }
}

impl core::fmt::Display for EtherAddress {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
      (self.0 & 0xFF0000000000) >> 40,
      (self.0 & 0xFF00000000) >> 32,
      (self.0 & 0xFF000000) >> 24,
      (self.0 & 0xFF0000) >> 16,
      (self.0 & 0xFF00) >> 8,
      self.0 & 0xFF,
    )
  }
}

type EtherProto = u16;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IPv4Address(u32);

impl IPv4Address {
  pub fn new(addr:u32) -> IPv4Address {
    IPv4Address(addr)
  }
}

impl core::fmt::Display for IPv4Address {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    write!(f, "{}.{}.{}.{}", 
      (self.0 & 0xFF000000) >> 24,
      (self.0 & 0xFF0000) >> 16,
      (self.0 & 0xFF00) >> 8,
      self.0 & 0xFF,
    )
  }
}


pub const ETH_PROTOCOL_IP:u16 = 0x800;
pub const ETH_PROTOCOL_ARP:u16 = 0x806;
pub const ETH_PROTOCOL_ELITE:u16 = 0x1337;
pub const ETH_BROADCAST_ADDRESS:EtherAddress = EtherAddress(0xFFFFFFFFFFFF);
pub const IPV4_TTL:u8 = 0x40;
pub const IP_PROTO_TCP:u8 = 0x06;
pub const IP_PROTO_UDP:u8 = 0x11;
pub const IP_BROADCAST_ADDRESS:IPv4Address = IPv4Address(0xffffffff);
pub const TCP_FLAG_NS:u16 = 0x100;
pub const TCP_FLAG_CWR:u16 = 0x80;
pub const TCP_FLAG_ECE:u16 = 0x40;
pub const TCP_FLAG_URG:u16 = 0x20;
pub const TCP_FLAG_ACK:u16 = 0x10;
pub const TCP_FLAG_PSH:u16 = 0x08;
pub const TCP_FLAG_RST:u16 = 0x04;
pub const TCP_FLAG_SYN:u16 = 0x02;
pub const TCP_FLAG_FIN:u16 = 0x01;
pub const DHCP_OPER_REQUEST:u8 = 0x1;
pub const DHCP_OPER_REPLY:u8 = 0x2;
pub const DHCP_HW_ETH:u8 = 0x1;
pub const DHCP_MAGIC:u32 = 0x63825363;
pub const DHCP_MSG_DISCOVER:u8 = 0x1;
pub const DHCP_MSG_OFFER:u8 = 0x2;
pub const DHCP_MSG_REQUEST:u8 = 0x3;
pub const DHCP_MSG_ACK:u8 = 0x5;
pub const DHCP_MSG_NAK:u8 = 0x6;
pub const DHCP_OPT_TYPE:u8 = 53;
pub const DHCP_OPT_REQUEST_IP:u8 = 50;
pub const DHCP_OPT_SUBNET_MASK:u8 = 1;
pub const DHCP_OPT_ROUTER:u8 = 3;
pub const DHCP_OPT_LEASE_TIME:u8 = 51;
pub const DHCP_OPT_DHCP_SERVER:u8 = 54;
pub const DHCP_OPT_DNS_SERVERS:u8 = 6;
pub const DHCP_OPT_END:u8 = 255;
pub const DHCP_CLI_PORT:u16 = 68;
pub const DHCP_SRV_PORT:u16 = 67;

#[derive(Debug)]
pub struct EtherHeader {
  pub dst: EtherAddress,
  pub src: EtherAddress,
  pub proto: EtherProto,
}

impl EtherHeader {
  pub fn new(dst:EtherAddress, src:EtherAddress, proto:EtherProto) -> EtherHeader {
    EtherHeader{dst, src, proto}
  }

  pub fn read(packet: &mut PacketReader) -> EtherHeader{
    // reading etheraddr's is a pain because they are 6 bytes
    let dst = EtherAddress(packet.read_u64_limited(6));
    let src = EtherAddress(packet.read_u64_limited(6));
    let proto = EtherProto::from(packet.read_u16());
    EtherHeader{dst, src, proto}
  }

  pub fn write(&self, packet: &mut PacketWriter) {
    packet.write_u64_limited(self.dst.0, 6);
    packet.write_u64_limited(self.src.0, 6);
    packet.write_u16(self.proto)
  }
}


impl core::fmt::Display for EtherHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
      let proto = match self.proto {
        ETH_PROTOCOL_ARP => "ARP",
        ETH_PROTOCOL_ELITE => "ELITE",
        ETH_PROTOCOL_IP => "IP",
        _ => "Unknown",
      };
      write!(f, "ETH SRC {} DST {} PROTO {} ({:X})", self.src, self.dst, proto, self.proto)
    }
}

const ARP_HARDWARE_TYPE_ETHERNET:u16 = 0x1;
const ARP_PROTOCOL_TYPE_IP:u16 = 0x800;
const ARP_OPERATION_REQUEST:u16 = 0x1;
#[allow(dead_code)]
const ARP_OPERATION_REPLY:u16 = 0x2;

#[derive(Debug)]
pub struct ArpHeader {
  pub hardware_type: u16,
  pub protocol_type: u16,
  pub hardware_len: u8,
  pub protocol_len: u8,
  pub operation: u16,
  pub sender_hardware_address: EtherAddress,
  pub sender_protocol_address: IPv4Address,
  pub target_hardware_address: EtherAddress,
  pub target_protocol_address: IPv4Address,
}

impl ArpHeader {
  pub fn new_request(source_ethernet: EtherAddress, source_ip: IPv4Address, target_ip: IPv4Address) -> ArpHeader {
    ArpHeader{
      hardware_type: ARP_HARDWARE_TYPE_ETHERNET,
      protocol_type: ARP_PROTOCOL_TYPE_IP,
      hardware_len: 6,
      protocol_len: 4,
      operation: ARP_OPERATION_REQUEST,
      sender_hardware_address: source_ethernet,
      sender_protocol_address: source_ip,
      target_hardware_address: EtherAddress(0),
      target_protocol_address: target_ip,
    }
  }

  pub fn write(&self, packet: &mut PacketWriter) {
    packet.write_u16(self.hardware_type);
    packet.write_u16(self.protocol_type);
    packet.write_u8(self.hardware_len);
    packet.write_u8(self.protocol_len);
    packet.write_u16(self.operation);
    packet.write_u64_limited(self.sender_hardware_address.0, 6);
    packet.write_u32(self.sender_protocol_address.0);
    packet.write_u64_limited(self.target_hardware_address.0, 6);
    packet.write_u32(self.target_protocol_address.0);
  }

  pub fn read(packet: &mut PacketReader) -> ArpHeader {
    let hardware_type = packet.read_u16();
    let protocol_type = packet.read_u16();
    let hardware_len = packet.read_u8();
    let protocol_len = packet.read_u8();
    let operation = packet.read_u16();
    let sender_hardware_address = EtherAddress(packet.read_u64_limited(6));
    let sender_protocol_address =  IPv4Address::new(packet.read_u32());
    let target_hardware_address = EtherAddress(packet.read_u64_limited(6));
    let target_protocol_address =  IPv4Address::new(packet.read_u32());
    ArpHeader{hardware_type, protocol_type, hardware_len, protocol_len, operation, sender_hardware_address, sender_protocol_address, target_hardware_address, target_protocol_address }
  }
}

impl core::fmt::Display for ArpHeader {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    match self.operation {
      ARP_OPERATION_REQUEST =>  write!(f, "ARP REQ Where is {}", self.target_protocol_address),
      ARP_OPERATION_REPLY => write!(f, "ARP REP {} is at {}", self.sender_protocol_address, self.sender_hardware_address),
      _ => write!(f, "ARP Unknown"),
    }

  }
}

#[allow(dead_code)]
pub struct IPv4Header {
  version_header_length: u8,
  tos: u8,
  len: u16,
  identification: u16,
  fragment_offset: u16,
  ttl: u8,
  pub proto: u8,
  checksum: u16,
  pub src: IPv4Address,
  pub dst: IPv4Address,
}

impl IPv4Header {
  pub fn new(src: IPv4Address, dst: IPv4Address, proto: u8, checksum: u16) -> IPv4Header {
    IPv4Header{
      version_header_length: 0x45,
      tos: 0x0,
      len: 0,
      identification: 0,
      fragment_offset: 0,
      ttl: IPV4_TTL,
      proto: proto,
      checksum: checksum,
      src: src,
      dst: dst,
    }
  }

  pub fn write(&self, packet: &mut PacketWriter) {
    let p = packet.start_packet_processor_u16();
    packet.write_u8(self.version_header_length);
    packet.write_u8(self.tos);
    packet.insert_len_result_u16(p);
    packet.write_u16(self.identification);
    packet.write_u16(self.fragment_offset);
    packet.write_u8(self.ttl);
    packet.write_u8(self.proto);
    packet.insert_crc_result_u16(p);
    packet.write_u32(self.src.0);
    packet.write_u32(self.dst.0);
    // ipv4 checksum is only on the headers
    packet.stop_crc(p);

    // calculate shadow sum for tcp and udp headers
    let mut shadow_sum = (self.src.0 >> 16) & 0xffff;
    shadow_sum += self.src.0 & 0xffff;
    let mut shadow_sum = (self.dst.0 >> 16) & 0xffff;
    shadow_sum += self.dst.0 & 0xffff;
    shadow_sum += self.proto as u32;
    packet.shadow_sum = shadow_sum;
  }

  pub fn read(packet: &mut PacketReader) -> IPv4Header {
    let version_header_length = packet.read_u8();
    let tos = packet.read_u8();
    let len = packet.read_u16();
    let identification = packet.read_u16();
    let fragment_offset = packet.read_u16();
    let ttl = packet.read_u8();
    let proto = packet.read_u8();
    let checksum = packet.read_u16();
    let src = IPv4Address(packet.read_u32());
    let dst = IPv4Address(packet.read_u32());
    IPv4Header{version_header_length, tos, len, identification, fragment_offset, ttl, proto, checksum, src, dst}
  }
}

impl core::fmt::Display for IPv4Header {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    let proto = match self.proto {
      IP_PROTO_TCP => "TCP",
      IP_PROTO_UDP => "UDP",
      _ => "UNKNOWN",
    };
    write!(f, "IP SRC {} DST {} proto {} len {}", self.src, self.dst, proto, self.len)
  }
}


#[allow(dead_code)]
pub struct TCPHeader {
  src_port: u16,
  dst_port: u16,
  seq: u32,
  ack: u32,
  data_offset: u8,
  flags: u16,
  checksum: u16,
  window_size: u16,
  urgent_pointer: u16,

}

impl TCPHeader {
  pub fn new(src_port: u16,dst_port: u16, seq: u32, ack:u32, data_offset: u8,flags: u16, checksum: u16, window_size:u16, urgent_pointer:u16) -> TCPHeader {
    TCPHeader{
      src_port,
      dst_port,
      seq,
      ack,
      data_offset,
      flags,
      window_size,
      checksum,
      urgent_pointer,
    }
  }

  pub fn write(&self, packet: &mut PacketWriter) {
    let p = packet.start_packet_processor_u16();
    packet.write_u16(self.src_port);
    packet.write_u16(self.dst_port);
    packet.write_u32(self.seq);
    packet.write_u32(self.ack);
    let data_offset_ns_bit = self.data_offset << 4 | ((self.flags | TCP_FLAG_NS) >> 8) as u8;
    packet.write_u8(data_offset_ns_bit);
    packet.write_u8(self.flags as u8);
    packet.write_u16(self.window_size);
    packet.insert_crc_result_u16(p);
    packet.write_u16(self.urgent_pointer);
  }

  pub fn read(packet: &mut PacketReader) -> TCPHeader {
    let src_port = packet.read_u16();
    let dst_port = packet.read_u16();
    let seq = packet.read_u32();
    let ack = packet.read_u32();
    let data_offset_ns_bit = packet.read_u8();
    let data_offset = data_offset_ns_bit >> 4;
    let flags = packet.read_u8() as u16 | ((data_offset_ns_bit as u16 & 0x1) << 8);
    let window_size = packet.read_u16();
    let checksum = packet.read_u16();
    let urgent_pointer = packet.read_u16();
    let opt_len = data_offset * 4 - 20;
    for _ in 0..opt_len {
      packet.read_u8();
    }
    TCPHeader{src_port, dst_port, seq, ack, data_offset, flags, window_size, checksum, urgent_pointer}
  }
}

impl core::fmt::Display for TCPHeader {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    let mut flags = Vec::<&str>::new();
    if self.flags & TCP_FLAG_ACK != 0 { flags.push("ACK")};
    if self.flags & TCP_FLAG_SYN != 0 { flags.push("SYN")};
    if self.flags & TCP_FLAG_RST != 0 { flags.push("RST")};
    if self.flags & TCP_FLAG_FIN != 0 { flags.push("FIN")};
    let flags_joined = flags.join(",");
    write!(f, "TCP SRC {} DST {} {}", self.src_port, self.dst_port, flags_joined)
  }
}

#[allow(dead_code)]
pub struct UDPHeader {
  pub src_port: u16,
  pub dst_port: u16,
  len: u16,
  checksum: u16
}

impl UDPHeader {
  pub fn new(src_port: u16,dst_port: u16, checksum: u16) -> UDPHeader {
    UDPHeader{
      src_port,
      dst_port,
      len: 0,
      checksum,
    }
  }
 
  pub fn write(&self, packet: &mut PacketWriter) {
    let p = packet.start_packet_processor_u16();
    packet.add_shadow_sum(p);
    packet.write_u16(self.src_port);
    packet.write_u16(self.dst_port);
    packet.insert_len_result_u16(p);
    packet.insert_crc_result_u16(p);
    // lazy: disabled crc for udp
    //packet.write_u16(0);
  }

  pub fn read(packet: &mut PacketReader) -> UDPHeader {
    let src_port = packet.read_u16();
    let dst_port = packet.read_u16();
    let len = packet.read_u16();
    let checksum = packet.read_u16();
    UDPHeader{src_port, dst_port, len, checksum}
  }
}

impl core::fmt::Display for UDPHeader {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    write!(f, "UDP SRC {} DST {}", self.src_port, self.dst_port)
  }
}



#[allow(dead_code)]
pub struct DHCPHeader {
  operation: u8,
  htype: u8,
  hlen: u8,
  hops: u8,
  xid: u32,
  seconds: u16,
  flags: u16,
  pub ciaddr: IPv4Address,
  pub yiaddr: IPv4Address,
  pub srvaddr: IPv4Address,
  pub gtwaddr: IPv4Address,
  cihwaddr: EtherAddress,
  pub dhcp_type: u8,
  dhcp_request_ip: IPv4Address,
  pub dhcp_subnet_mask: IPv4Address,
  pub dhcp_router: IPv4Address,
  dhcp_server: IPv4Address,
  pub dhcp_lease_time: u32,
  pub dhcp_dns_servers: Vec<IPv4Address>,

}

impl DHCPHeader {
  pub fn new_discover(mac: EtherAddress) -> DHCPHeader {
    DHCPHeader{
      operation: DHCP_OPER_REQUEST, 
      htype: DHCP_HW_ETH,
      hlen: 0x6,
      hops: 0,
      xid: 0xdeadbeef,
      seconds: 0,
      flags: 0,
      ciaddr: IPv4Address(0),
      yiaddr: IPv4Address(0),
      srvaddr: IPv4Address(0),
      gtwaddr: IPv4Address(0),
      cihwaddr: mac,
      dhcp_type: DHCP_MSG_DISCOVER,
      dhcp_request_ip: IPv4Address(0),
      dhcp_subnet_mask: IPv4Address(0),
      dhcp_router: IPv4Address(0),
      dhcp_server: IPv4Address(0),
      dhcp_lease_time: 0,
      dhcp_dns_servers: Vec::new(),
    }
  }

  pub fn new_request(mac: EtherAddress, srvaddr: IPv4Address, myaddr: IPv4Address) -> DHCPHeader {
    DHCPHeader{
      operation: DHCP_OPER_REQUEST, 
      htype: DHCP_HW_ETH,
      hlen: 0x6,
      hops: 0,
      xid: 0xdeadbeef,
      seconds: 0,
      flags: 0,
      ciaddr: myaddr,
      yiaddr: IPv4Address(0),
      srvaddr: srvaddr,
      gtwaddr: IPv4Address(0),
      cihwaddr: mac,
      dhcp_type: DHCP_MSG_REQUEST,
      dhcp_request_ip: myaddr,
      dhcp_subnet_mask: IPv4Address(0),
      dhcp_router: IPv4Address(0),
      dhcp_server: srvaddr,
      dhcp_lease_time: 0,
      dhcp_dns_servers: Vec::new(),
    }
  }


  pub fn write(&self, packet: &mut PacketWriter) {
    packet.write_u8(self.operation);
    packet.write_u8(self.htype);
    packet.write_u8(self.hlen);
    packet.write_u8(self.hops);
    packet.write_u32(self.xid);
    packet.write_u16(self.seconds);
    packet.write_u16(self.flags);
    packet.write_u32(self.ciaddr.0);
    packet.write_u32(self.yiaddr.0);
    packet.write_u32(self.srvaddr.0);
    packet.write_u32(self.gtwaddr.0);
    packet.write_u64_limited(self.cihwaddr.0,6);
    // bootp legacy padding
    for _ in 0..202 { packet.write_u8(0);}
    packet.write_u32(DHCP_MAGIC);
    
    // dhcp message type
    packet.write_u8(DHCP_OPT_TYPE);
    packet.write_u8(1);
    packet.write_u8(self.dhcp_type);
    if self.dhcp_type == DHCP_MSG_REQUEST {
      packet.write_u8(DHCP_OPT_REQUEST_IP);
      packet.write_u8(4);
      packet.write_u32(self.dhcp_request_ip.0);
      packet.write_u8(DHCP_OPT_DHCP_SERVER);
      packet.write_u8(4);
      packet.write_u32(self.dhcp_server.0);
    }
    packet.write_u8(DHCP_OPT_END);
  }

  pub fn read(packet: &mut PacketReader) -> DHCPHeader {
    let operation = packet.read_u8();
    let htype = packet.read_u8();
    let hlen = packet.read_u8();
    let hops = packet.read_u8();
    let xid = packet.read_u32();
    let seconds = packet.read_u16();
    let flags = packet.read_u16();
    let ciaddr = IPv4Address(packet.read_u32());
    let yiaddr = IPv4Address(packet.read_u32());
    let srvaddr = IPv4Address(packet.read_u32());
    let gtwaddr = IPv4Address(packet.read_u32());
    let cihwaddr = EtherAddress(packet.read_u64_limited(6));
    for _ in 0..206 { packet.read_u8();}
    let mut dhcp_type = 0;
    let dhcp_request_ip = IPv4Address(0);
    let mut dhcp_subnet_mask = IPv4Address(0);
    let mut dhcp_router = IPv4Address(0);
    let dhcp_server = IPv4Address(0);
    let mut dhcp_lease_time = 0;
    let mut dhcp_dns_servers = Vec::new();
    loop {
      let optype = packet.read_u8();
      let len = packet.read_u8();
      match optype {
        DHCP_OPT_TYPE => { dhcp_type = packet.read_u8() },
        DHCP_OPT_SUBNET_MASK => { dhcp_subnet_mask = IPv4Address(packet.read_u32())},
        DHCP_OPT_ROUTER => { dhcp_router = IPv4Address(packet.read_u32())},
        DHCP_OPT_LEASE_TIME => {dhcp_lease_time = packet.read_u32()},
        DHCP_OPT_DNS_SERVERS => { 
          for _ in 0..(len/4) {
            let dns_server = IPv4Address(packet.read_u32());
            dhcp_dns_servers.push(dns_server);
          }
        },
        
        DHCP_OPT_END => { break },
        _ => { 
          // skip this one...
          for _ in 0..len {
            packet.read_u8();
          }
        },
      }
    }
    DHCPHeader{
      operation, htype, hlen, hops, xid, seconds, flags, ciaddr, yiaddr, srvaddr, gtwaddr, cihwaddr, dhcp_type,
      dhcp_request_ip, dhcp_subnet_mask, dhcp_router, dhcp_server, dhcp_lease_time, dhcp_dns_servers
    }
  }
}

impl core::fmt::Display for DHCPHeader {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    if self.dhcp_type == DHCP_MSG_OFFER {
      write!(f, "DHCP OFFER {}", self.yiaddr)
    } else if self.dhcp_type == DHCP_MSG_ACK {
      write!(f, "DHCP ACK {}", self.yiaddr)
    } else {
      write!(f, "DHCP {}", self.dhcp_type)
    }
  }
}
