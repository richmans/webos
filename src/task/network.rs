use x86_64::instructions::port::Port;
use conquer_once::spin::OnceCell;
use crossbeam_queue::ArrayQueue;
use core::{pin::Pin, task::{Poll, Context}};
use futures_util::stream::Stream;
use crate::println;
use futures_util::task::AtomicWaker;
use futures_util::stream::StreamExt;
use crate::network;
use x86_64::VirtAddr;

static WAKER: AtomicWaker = AtomicWaker::new();
static PACKET_QUEUE: OnceCell<ArrayQueue<u16>> = OnceCell::uninit();
static INTERRUPT_STATUS_PORT: OnceCell<u16> = OnceCell::uninit();
const ROK_INT_BIT:u16 =0x1;
const TOK_INT_BIT:u16 =0x4;

pub struct PacketStream {
  _private: (),
}

impl PacketStream {
  pub fn new(interrupt_status_port:u16) -> Self {
    INTERRUPT_STATUS_PORT.init_once(|| interrupt_status_port);
    let ps=PacketStream { _private: ()};
    PACKET_QUEUE.try_init_once(|| ArrayQueue::new(100))
          .expect("PacketStream::new should only be called once");
    ps
  }
  
}

impl Stream for PacketStream {
  type Item = u16;

  fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<u16>> {
    let queue = PACKET_QUEUE
        .try_get()
        .expect("packet queue not initialized");

    // fast path
    if let Ok(packet) = queue.pop() {
        return Poll::Ready(Some(packet));
    }

    WAKER.register(&cx.waker());
    match queue.pop() {
        Ok(packet) => {
            WAKER.take();
            Poll::Ready(Some(packet))
        }
        Err(crossbeam_queue::PopError) => Poll::Pending,
    }
  } 
}

fn ack_interrupt() {
    let mut isr_port = Port::<u16>::new(*INTERRUPT_STATUS_PORT.get().expect("Interrupt status port not found"));
    unsafe {
        let isr_value = 5;
        isr_port.write(isr_value);
    }
}

/// Called by the network interrupt handler
pub(crate) fn add_packet(packet: u16) {
  if let Ok(queue) = PACKET_QUEUE.try_get() {
      if let Err(_) = queue.push(packet) {
          panic!("WARNING: packet queue full; dropping network input");
      } else {
          WAKER.wake();
      }
      
  } else {
      println!("WARNING: packet queue uninitialized");
  }
  ack_interrupt();
}

// this function is called by the interrupt handler
pub(crate) fn handle_interrupt() {
    let mut isr_port = Port::<u16>::new(*INTERRUPT_STATUS_PORT.get().expect("Interrupt status port not found"));
    let isr_value = unsafe { isr_port.read() };
    add_packet(isr_value)
}

pub async fn process_packets(network_buffer:VirtAddr){
  let mut network = network::init(network_buffer);
  let interrupt_status_port = network.interrupt_status_port();
  let mut packets = PacketStream::new(interrupt_status_port);
  network.send_network_announcement();
  network.send_dhcp_discover();
  while let Some(packet) = packets.next().await {
      // if the event was a receive ok
      if packet & ROK_INT_BIT != 0 {
        network.read_packet_header();
      }
      // if the event was a transmit ok
      if packet & TOK_INT_BIT != 0 {
          // do something else
      }
  }
}