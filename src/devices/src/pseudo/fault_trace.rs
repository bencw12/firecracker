use crate::BusDevice;
use logger::info;
use snapshot::Persist;
use std::convert::TryInto;
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

pub const TRACE_PORT: u64 = 0x80;

#[derive(Debug, Versionize, Clone, Copy)]
pub enum State {
    Init,
    Tracing,
}

#[derive(Versionize)]
pub struct FaultTracerState {
    pub trace_base: u64,
    pub state: State,
}

pub struct FaultTracerConstructorArgs {
    pub mem: GuestMemoryMmap,
}

#[derive(Debug)]
pub struct FaultTracer {
    mem: GuestMemoryMmap,
    trace_base: u64,
    state: State,
    log: File,
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
    pub fn new(mem: GuestMemoryMmap) -> Self {
        let path = "/tmp/fc-trace.log";
        match fs::remove_file(path) {
            Err(e) if e.kind() != ErrorKind::NotFound => {
                panic!(e)
            }
            _ => {}
        }
        let log = File::create(path).unwrap();

        FaultTracer {
            mem,
            trace_base: 0,
            state: State::Init,
            log,
        }
    }

    pub fn from_state(mem: GuestMemoryMmap, state: &FaultTracerState) -> Self {
        let mut tracer = Self::new(mem);
        tracer.trace_base = state.trace_base;
        tracer.state = state.state;
        return tracer;
    }

    fn read_trace(&mut self, num_entries: usize) {
        let mut ents = Vec::with_capacity(num_entries);
        let ent_size = std::mem::size_of::<Fault>();

        info!("reading trace: {}", num_entries);

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

            writeln!(
                self.log,
                "fault: type = {}, addr = 0x{:x}, comm = {}",
                kind, addr, comm
            )
            .unwrap();
        }
    }
}

impl BusDevice for FaultTracer {
    fn read(&mut self, _offset: u64, _data: &mut [u8]) {
        info!("read from fault tracer");
    }

    fn write(&mut self, _offset: u64, data: &[u8]) {
        match self.state {
            State::Init => {
                self.trace_base = u64::from_le_bytes(data.try_into().unwrap());
                self.state = State::Tracing;
                info!("trace_base=0x{:x}", self.trace_base);
            }
            State::Tracing => {
                let num_entries = u64::from_le_bytes(data.try_into().unwrap());
                self.read_trace(num_entries as usize);
            }
        }
    }
}

impl Persist<'_> for FaultTracer {
    type State = FaultTracerState;
    type ConstructorArgs = FaultTracerConstructorArgs;
    type Error = ();
    fn save(&self) -> Self::State {
        FaultTracerState {
            trace_base: self.trace_base,
            state: self.state,
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        info!("FAULT TRACER RESTORE");
        let tracer = Self::from_state(constructor_args.mem, state);
        Ok(tracer)
    }
}
