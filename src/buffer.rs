pub const PACKET_SIZE:usize = 1800;
use alloc::vec::Vec;
pub type Packet = [u8; PACKET_SIZE];

struct CRCProcessorU16 {
  sum: u32,
  len: u16,
  highbyte: bool,
  insert_crc_at: Option<usize>,
  insert_len_at: Option<usize>,
  crc_enabled: bool,
}

impl CRCProcessorU16 {
  fn process(&mut self, data:u8) {
    self.len += 1;
    if self.crc_enabled {
      
      self.sum += match self.highbyte {
        true => (data as u32) << 8,
        false => data as u32,
      };
      
    }
    self.highbyte = !self.highbyte;
  }

  fn set_crc_insertion(&mut self, insert_at: usize) {
    self.insert_crc_at = Some(insert_at);
  }

  fn set_len_insertion(&mut self, insert_at: usize) {
    self.insert_len_at = Some(insert_at);
  }

  fn stop_crc(&mut self) {
    self.crc_enabled = false;
  }

  fn finish(&mut self) -> (Option<usize>, u16, Option<usize>, u16){
    let mut crc = self.sum; 
    //gocha: the len header should also be in the checksum
    crc += self.len as u32;
    while crc > 0xFFFF {
      crc = (crc & 0xFFFF) + (crc >> 16);
    }
    crc = !crc;
    (self.insert_crc_at, crc as u16, self.insert_len_at, self.len as u16)
  }  
}

pub struct PacketReader<'a> {
  pub ptr: usize,
  pub data: &'a Packet,
}
pub struct PacketWriter<'a> {
  pub ptr: usize,
  pub data: &'a mut Packet,
  processing: bool,
  processors: Vec<CRCProcessorU16>,
}

impl<'a> PacketWriter<'a> {
  pub fn new(data: &'a mut Packet) -> PacketWriter {
    PacketWriter{ptr: 0, data, processing: true, processors: Vec::<CRCProcessorU16>::new()}
  }

  pub fn start_packet_processor_u16(&mut self) -> usize {
    let processor = CRCProcessorU16{len:0, sum: 0, highbyte: true, insert_crc_at:None, insert_len_at: None, crc_enabled: true};
    let idx = self.processors.len();
    self.processors.push(processor);
    idx
  }

  pub fn insert_crc_result_u16(&mut self, idx: usize) {
    self.processors[idx].set_crc_insertion( self.ptr );
    self.write_u16(0);
  }

  pub fn insert_len_result_u16(&mut self, idx: usize) {
    self.processors[idx].set_len_insertion( self.ptr );
    self.write_u16(0);
  }
  
  pub fn stop_crc(&mut self, idx:usize) {
    self.processors[idx].stop_crc();
  }

  pub fn finish(&mut self) {
    self.processing = false;
    let mut mutations = Vec::<(usize, u16)>::new();
    for p in self.processors.iter_mut() {
      let result = p.finish();
      match result.0 {
        Some(n) => mutations.push((n, result.1)),
        None => {},
      }
      match result.2 {
        Some(n) => mutations.push((n, result.3)),
        None => {},
      }
      
    }
    for m in mutations {
      let ptr = self.ptr;
      self.ptr = m.0 as usize;
      self.write_u16(m.1);
      self.ptr = ptr;
    }
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
      if self.processing {
        for b in self.processors.iter_mut() {
          b.process(data)
        }
      }
  }

  pub fn write(&mut self, data: &[u8]) {
    for c in 0..data.len() {
      self.write_u8(data[c])
    }
  }
}

impl<'a> PacketReader<'a> {
  pub fn new(data: &'a Packet) -> PacketReader {
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

  pub fn read_u16_le(&mut self) -> u16 {
    let mut r:u16 = 0;
    for n in 0..2 {
      r += (self.read_u8() as u16) << n*8;
    }
    r
  }

  pub fn read_u8(&mut self) -> u8{
    self.ptr += 1;
    self.data[self.ptr-1]
  }
}