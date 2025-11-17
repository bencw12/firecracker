use crate::bus::BusDevice;
use utils::eventfd::EventFd;
use versionize_derive::Versionize;
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use vm_memory::{GuestMemoryMmap, GuestAddress, Bytes, ByteValued};
use logger::{info, error};
use snapshot::Persist;
use std::convert::TryInto;

use super::TASK_COMM_LEN;

#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct PageTraceEntry {
    mapping_type: u64,
    addr: u64,
    comm: [u8; TASK_COMM_LEN],
}

#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct WsRegion {
    pfn: u64, // pfn
    len: u64 // # pages
}


unsafe impl ByteValued for PageTraceEntry {}
unsafe impl ByteValued for WsRegion {}

pub enum State {
    ReadWsLen,
    ReadWs,
    Tracing,
    Init,
}

pub struct MemTracer {
    interrupt_evt: EventFd,
    mem: GuestMemoryMmap,
    trace_base: u64,
    state: State,
    trace: Vec<PageTraceEntry>,
    working_set: Vec<Vec<i64>>,
}

#[derive(Versionize)]
pub struct MemTracerState {
    pub trace_base: u64,
}

pub struct MemTracerConstructorArgs {
    pub mem: GuestMemoryMmap,
}

const N_ENTRIES: usize = 4096 / std::mem::size_of::<PageTraceEntry>();

impl BusDevice for MemTracer {
    fn read(&mut self, _offset: u64, data: &mut [u8]) {
        match self.state {
            State::ReadWsLen => {
                info!("sending ws len to guest {}", self.working_set.len());
                let len_buf = u64::to_le_bytes(self.working_set.len() as u64);
                data.copy_from_slice(&len_buf);
                self.state = State::ReadWs;
            },
            State::ReadWs => {
                let mut n = 0;
                let max_to_send = 4096 / std::mem::size_of::<WsRegion>();
                info!("guest read chunk of working set");
                while n < max_to_send {
                    let entry = self.working_set.pop();
                    if entry.is_none() {
                        info!("finished entries");
                        break;
                    }
                    let entry = entry.unwrap();

                    let pfn = *entry.get(0).unwrap() as u64;
                    let len = *entry.get(1).unwrap() as u64;

                    let region = WsRegion {
                        pfn,
                        len,
                    };

                    info!("region {:?}", region);

                    let guest_addr = self.trace_base +
                        (n * std::mem::size_of::<WsRegion>()) as u64;
                    self.mem.write_obj(region, GuestAddress(guest_addr));
                    n += 1;
                }

                info!("send {} entries", n);

                let len_buf = u64::to_le_bytes(n as u64);
                data.copy_from_slice(&len_buf);

                if self.working_set.is_empty() {
                    self.state = State::Tracing;
                }
            }
            _ => {
                error!("invalid state");
            }
        }
    }
    fn write(&mut self, _offset: u64, data: &[u8]) {
        match self.state {
            State::Init => {
                self.trace_base = u64::from_le_bytes(data.try_into().unwrap());
                self.state = State::ReadWsLen;
                info!("mem trace base = 0x{:x}", self.trace_base);
            },
            State::Tracing => {
                info!("mem tracer got write from guest");
                for i in 0..N_ENTRIES {
                    let addr = self.trace_base +
                        (i * std::mem::size_of::<PageTraceEntry>()) as u64;
                    let entry: PageTraceEntry =
                        self.mem.read_obj(GuestAddress(addr)).unwrap();

                    // mapping type is > 0
                    if entry.mapping_type == 4 {
                        break;
                    }

                    info!("addr=0x{:x} type={} comm={}",
                          entry.addr, entry.mapping_type,
                          String::from_utf8_lossy(&entry.comm.to_vec()).to_string());
                }
            },
            _ => { error!("invalid tracer state for guest write") },
        }
    }

    fn interrupt(&self, _irq_mask: u32) -> std::io::Result<()> {
        self.interrupt_evt.write(1)
    }
}

impl MemTracer {
    pub fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    pub fn start_trace(&mut self, ws_regions: &Vec<Vec<i64>>) {
        info!("mem tracer sending interrupt");
        self.working_set = ws_regions.clone();
        self.interrupt(0).unwrap();
    }

    pub fn end_trace(&mut self) {
        info!("sending interrupt to end mem trace");
        self.interrupt(0).unwrap();
    }

    pub fn new(mem: GuestMemoryMmap) -> Self {
        MemTracer {
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            mem,
            trace_base: 0,
            state: State::Init,
            trace: Vec::new(),
            working_set: Vec::new(),
        }
    }
}

impl Persist<'_> for MemTracer {
    type State = MemTracerState;
    type ConstructorArgs = MemTracerConstructorArgs;
    type Error = ();
    fn save (&self) -> Self::State {
        MemTracerState {
            trace_base: self.trace_base,
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        let mut tracer = Self::new(constructor_args.mem);
        tracer.trace_base = state.trace_base;
        tracer.state = State::ReadWsLen;
        Ok(tracer)
    }
}
