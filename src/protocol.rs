use crate::buffer::{PacketWriter, PacketReader};

pub const ETH_PROTOCOL_IP:u16 = 0x800;
pub const ETH_PROTOCOL_ARP:u16 = 0x806;
pub const ETH_PROTOCOL_ELITE:u16 = 0x1337;
pub const ETH_BROADCAST_ADDRESS:u64 = 0xFFFFFFFFFFFF;
type EtherAddress = u64;
type EtherProto = u16;
type IPv4Address = u32;

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
    let dst = packet.read_u64_limited(6);
    let src = packet.read_u64_limited(6);
    let proto = EtherProto::from(packet.read_u16());
    EtherHeader{dst, src, proto}
  }

  pub fn write(&self, packet: &mut PacketWriter) {
    packet.write_u64_limited(self.dst as u64, 6);
    packet.write_u64_limited(self.src as u64, 6);
    packet.write_u16(self.proto)
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
      target_hardware_address: 0,
      target_protocol_address: target_ip,
    }
  }

  pub fn write(&self, packet: &mut PacketWriter) {
    packet.write_u16(self.hardware_type);
    packet.write_u16(self.protocol_type);
    packet.write_u8(self.hardware_len);
    packet.write_u8(self.protocol_len);
    packet.write_u16(self.operation);
    packet.write_u64_limited(self.sender_hardware_address, 6);
    packet.write_u32(self.sender_protocol_address);
    packet.write_u64_limited(self.target_hardware_address, 6);
    packet.write_u32(self.target_protocol_address);
  }
}