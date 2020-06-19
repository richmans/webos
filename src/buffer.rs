pub const PACKET_SIZE:usize = 1800;

pub type Packet = [u8; PACKET_SIZE];

pub struct PacketReader<'a> {
  pub ptr: usize,
  pub data: &'a mut Packet,
}
pub struct PacketWriter<'a> {
  pub ptr: usize,
  pub data: &'a mut Packet,
}


impl<'a> PacketWriter<'a> {
  pub fn new(data: &'a mut Packet) -> PacketWriter {
    PacketWriter{ptr: 0, data}
  }

  pub fn write_u64_limited(&mut self, data:u64, len:usize) {
    let skip_bytes = 8 - len;
    for c in data.to_be_bytes()[skip_bytes..].iter() {
      self.write_u8(*c);
    }
  } 

  pub fn write_u64(&mut self, data:u64) {
    for c in data.to_be_bytes().iter() {
      self.write_u8(*c);
    }
  } 

  pub fn write_u32(&mut self, data:u32) {
    for c in data.to_be_bytes().iter() {
      self.write_u8(*c);
    }
  } 

  pub fn write_u16(&mut self, data:u16) {
    for c in data.to_be_bytes().iter() {
      self.write_u8(*c);
    }
  } 

  pub fn write_u8(&mut self, data:u8) {
      self.data[self.ptr] = data;
      self.ptr += 1;
  }

  pub fn write(&mut self, data: &[u8]) {
    for c in 0..data.len() {
      self.write_u8(data[c])
    }
  }
}

impl<'a> PacketReader<'a> {
  pub fn new(data: &'a mut Packet) -> PacketReader {
    PacketReader{ptr: 0, data}
  }

  pub fn read_u64_limited(&mut self, limit: u8) -> u64{
    let mut r: u64 = 0;
    for _ in 0..limit {
      r = r << 8;
      r += self.read_u8() as u64
    }
    r
  }
 
  pub fn read_u64(&mut self) -> u64{
    let mut r: u64 = 0;
    for _ in 0..8 {
      r = r << 8;
      r += self.read_u8() as u64
    }
    r
  }
 
  pub fn read_u32(&mut self) -> u32 {
    let mut r:u32 = 0;
    for _ in 0..4 {
      r = r << 8;
      r += self.read_u8() as u32
    }
    r
  }

  pub fn read_u16(&mut self) -> u16 {
    let mut r:u16 = 0;
    for _ in 0..2 {
      r = r << 8;
      r += self.read_u8() as u16
    }
    r
  }

  pub fn read_u8(&mut self) -> u8{
    self.ptr += 1;
    20
  }
}