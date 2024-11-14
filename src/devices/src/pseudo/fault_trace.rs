use crate::BusDevice;
use vm_memory::{Bytes, ByteValued, GuestAddress, GuestMemoryMmap};
use logger::info;
use std::convert::TryInto;

pub const TRACE_PORT: u64 = 0x80;

#[derive(Debug)]
enum State {
    AddrHigh,
    AddrLow,
    Tracing,
}

#[derive(Debug)]
pub struct FaultTracer {
    mem: GuestMemoryMmap,
    trace_base: u64,
    state: State,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
struct Fault {
    kind: u64,
    addr: u64,
    comm: [u8; 16],
}

unsafe impl ByteValued for Fault {}

impl FaultTracer {
    pub fn new(
	mem: GuestMemoryMmap,
    ) -> Self {
	FaultTracer {
	    mem,
	    trace_base: 0,
	    state: State::AddrHigh,
	}
    }
    
    fn read_trace(&mut self, num_entries: usize) {
	let mut ents = Vec::with_capacity(num_entries);
	let ent_size = std::mem::size_of::<Fault>();

	for i in 0..num_entries {
	    let addr = GuestAddress(self.trace_base + ((ent_size * i) as u64));
	    let mut ent = self.mem.read_obj::<Fault>(addr).unwrap();
	    ents.push(ent);

	    let mut fill = false;
	    for j in 0..16 {
		if ent.comm[j] == 0 {
		    fill = true;
		}

		if fill {
		    ent.comm[j] = 0;
		}
	    }
	    
	    let comm = String::from_utf8_lossy(&ent.comm.to_vec()).to_string();
	    let kind = ent.kind;
	    let addr = ent.addr;
	    info!("fault: type = {}, addr = 0x{:x}, comm = {}",
		  kind, addr, comm);
	}	
    }
}

impl BusDevice for FaultTracer {
    fn read(&mut self, _offset: u64, _data: &mut [u8]) {
	info!("read from fault tracer");
    }

    fn write(&mut self, _offset: u64, data: &[u8]) {
	match self.state {
	    State::AddrHigh => {
		let high = u32::from_le_bytes(data.try_into().unwrap());
		self.trace_base = high as u64;
		self.state = State::AddrLow;
		info!("upper 4 bytes = 0x{:x}", high);
	    },
	    State::AddrLow => {
		let low = u32::from_le_bytes(data.try_into().unwrap());
		self.trace_base = (self.trace_base << 32) | low as u64;
		self.state = State::Tracing;
		info!("full address = 0x{:x}", self.trace_base);
	    },
	    State::Tracing => {
		let num_entries = u32::from_le_bytes(data.try_into().unwrap());
		self.read_trace(num_entries as usize);
	    },
	}
    }
}
