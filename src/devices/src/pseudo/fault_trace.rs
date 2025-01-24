use crate::BusDevice;
use logger::info;
use snapshot::Persist;
use std::convert::TryInto;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::{ErrorKind, Write};
use utils::eventfd::EventFd;
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

pub const TRACE_PORT: u64 = 0x80;
pub const MEM_TRACE_PATH: &str = "/tmp/fc-mem.log";

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

pub struct FaultTracer {
    mem: GuestMemoryMmap,
    trace_base: u64,
    state: State,
    log: File,
    mem_trace: Option<File>,
    interrupt_evt: EventFd,
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
    pub fn new(mem: GuestMemoryMmap) -> io::Result<Self> {
        let path = "/tmp/fc-trace.log";
        match fs::remove_file(path) {
            Err(e) if e.kind() != ErrorKind::NotFound => {
                panic!(e)
            }
            _ => {}
        }
        let log = File::create(path).unwrap();

        let tracer = FaultTracer {
            mem,
            trace_base: 0,
            state: State::Init,
            log,
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK)?,
            mem_trace: None,
        };

        Ok(tracer)
    }

    pub fn from_state(mem: GuestMemoryMmap, state: &FaultTracerState) -> Self {
        let path = "/tmp/fc-trace.log";
        match fs::remove_file(path) {
            Err(e) if e.kind() != ErrorKind::NotFound => {
                panic!(e)
            }
            _ => {}
        }

        let log = File::create(path).unwrap();

        let tracer = FaultTracer {
            state: state.state,
            trace_base: state.trace_base,
            mem,
            log,
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(), // todo don't panic
            mem_trace: None,
        };

        tracer
    }

    pub fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    pub fn do_mem_trace(&mut self) {
        self.mem_trace = Some(OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(MEM_TRACE_PATH).unwrap());

        info!("doing memory trace!");
        self.interrupt(0).unwrap();
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

            let kind = ent.kind;
            let addr = ent.addr;

            if self.mem_trace.is_some() && kind == 2 {
                writeln!(self.mem_trace.as_ref().unwrap(), "kaddr = 0x{:x}", addr,).unwrap();
            }

            if self.mem_trace.is_some() && kind == 3 {
                // write to mem trace
                let comm = String::from_utf8_lossy(&ent.comm.to_vec()).to_string();
                writeln!(
                    self.mem_trace.as_ref().unwrap(),
                    "addr = 0x{:x}, comm = {}",
                    addr,
                    comm
                )
                .unwrap();
            } else if self.mem_trace.is_some() && kind == 4 {
                writeln!(self.mem_trace.as_ref().unwrap(), "done",).unwrap();
            } else {
                // write to fault trace
                writeln!(self.log, "fault: type = {}, addr = 0x{:x}", kind, addr).unwrap();
            }
        }
    }
}

impl BusDevice for FaultTracer {
    fn read(&mut self, _offset: u64, _data: &mut [u8]) {
        info!("read from fault tracer");
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        match self.state {
            State::Init => {
                self.trace_base = u64::from_le_bytes(data.try_into().unwrap());
                self.state = State::Tracing;
                info!("trace_base=0x{:x}", self.trace_base);
            }
            State::Tracing => {
                if offset == 4 {
                    let proc_nr = u32::from_le_bytes(data.try_into().unwrap());
                    info!("proc nr = {}", proc_nr);
                    return;
                }

                if offset == 8 {
                    let mmap_nr = u32::from_le_bytes(data.try_into().unwrap());
                    info!("mmap nr = {}", mmap_nr);
                    return;
                }

                let num_entries = u64::from_le_bytes(data.try_into().unwrap());
                self.read_trace(num_entries as usize);
            }
        }
    }

    fn interrupt(&self, _irq_mask: u32) -> std::io::Result<()> {
        self.interrupt_evt.write(1).unwrap();
        Ok(())
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
        let tracer = Self::from_state(constructor_args.mem, state);
        Ok(tracer)
    }
}
