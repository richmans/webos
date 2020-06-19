use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use crate::println;
use lazy_static::lazy_static;

#[cfg(test)]
use crate::{serial_print, serial_println};

use crate::print;

use pic8259_simple::ChainedPics;
use spin;

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: spin::Mutex<ChainedPics> =
    spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

    use crate::gdt;
lazy_static! {
    
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe {
            idt.double_fault.set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX); // new
        }
        idt[InterruptIndex::Timer.as_usize()]
            .set_handler_fn(timer_interrupt_handler); // new
        idt[InterruptIndex::Keyboard.as_usize()]
            .set_handler_fn(keyboard_interrupt_handler);
        idt[InterruptIndex::Network.as_usize()]
            .set_handler_fn(network_interrupt_handler);
        idt
    };
    
        
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
    Network = PIC_1_OFFSET + 0xb,

}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}


pub fn init_pics() {
    unsafe {
        use x86_64::instructions::port::Port;
        const PIC1: u16 = 0x20;		/* IO base address for master PIC */
        const PIC2:u16 = 0xA0;		/* IO base address for slave PIC */
        const PIC1_COMMAND:u16 = PIC1;
        const PIC1_DATA:u16 = PIC1+1;
        const PIC2_COMMAND:u16 = PIC2;
        const PIC2_DATA:u16 = PIC2+1;
        const CMD_INIT: u8 = 0x11;
        const WAIT_PORT:u16 = 0x80;
        const MODE_8086: u8 = 0x01;

        let mut wait_port = Port::<u8>::new(WAIT_PORT);
        let mut pic1_data = Port::<u8>::new(PIC1_DATA);
        let mut pic2_data = Port::<u8>::new(PIC2_DATA);
        let mut pic1_command = Port::<u8>::new(PIC1_COMMAND);
        let mut pic2_command = Port::<u8>::new(PIC2_COMMAND);
        let mut wait = || { wait_port.write(0) };

        //command pics into 3-stage setup mode
        pic1_command.write(CMD_INIT);
        wait();
        pic2_command.write(CMD_INIT);
        wait();

        //offset setup
        pic1_data.write(PIC_1_OFFSET);
        wait();
        pic2_data.write(PIC_2_OFFSET);
        wait();
        
        //chaining setup
        pic1_data.write(4);
        wait();
        pic2_data.write(2);
        wait();

        // 8086 mode (oldschool)
        pic1_data.write(MODE_8086);
        wait();
        pic2_data.write(MODE_8086);
        wait();

        pic1_data.write(0x10);
        wait();
        pic2_data.write(0x80);
     
    }
}
pub fn init_idt() {
    IDT.load();
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: &mut InterruptStackFrame) {
    println!("Exception: Breakpoint\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(stack_frame: &mut InterruptStackFrame, _error_code: u64) -> ! {
    println!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
    loop {}
}

extern "x86-interrupt" fn network_interrupt_handler(_stack_frame: &mut InterruptStackFrame) {
    use x86_64::instructions::port::Port;
    let portnum = 0xc03c;
    let mut imr_port = Port::<u16>::new(portnum);
    unsafe {
        println!("INT: Network interrupt received. Disabling network interrupts for now");
        imr_port.write(0x0);
        
    }
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Network.as_u8());
    }
}
extern "x86-interrupt" fn timer_interrupt_handler(
    _stack_frame: &mut InterruptStackFrame)
{
    //print!(".");
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}

extern "x86-interrupt" fn keyboard_interrupt_handler(
    _stack_frame: &mut InterruptStackFrame)
{
    use x86_64::instructions::port::Port;
    let mut port = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };
    print!("{}", scancode);
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}

#[test_case]
fn test_breakpoint_exception() {
    serial_print!("test_breakpoint_exception...");
    // invoke a breakpoint exception
    x86_64::instructions::interrupts::int3();
    serial_println!("[ok]");
}