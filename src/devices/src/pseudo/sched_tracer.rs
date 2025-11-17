
use crate::bus::BusDevice;
use logger::{info, error};
use net_gen::__pid_t;
use utils::eventfd::EventFd;
use snapshot::Persist;
use versionize_derive::Versionize;
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use vm_memory::{GuestMemoryMmap, GuestAddress, Bytes, ByteValued};
use core::arch::x86_64::_rdtsc;
use std::convert::TryInto;

use super::TASK_COMM_LEN;

#[derive(Debug, Versionize, Clone, Copy)]
enum State {
    Init,
    Tracing,
}

pub struct SchedTracer {
    interrupt_evt: EventFd, // send interrupts
    pid: u16, // guest pid to trace
    mem: GuestMemoryMmap, // to read the comm
    trace_base: u64, // base in guest memory where comm names are written
    state: State,
    trace: Vec<SchedTraceEntry>,
    done_tracing: bool,
    overhead: u64,
    tsc_start: u64,
}

#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
pub struct SchedTraceEntry {
    comm: [u8; TASK_COMM_LEN],
    tsc: u64,
}

unsafe impl ByteValued for SchedTraceEntry {}

#[derive(Versionize)]
pub struct SchedTracerState {
    pub pid: u16,
    pub trace_base: u64,
}

pub struct SchedTracerConstructorArgs {
    pub mem: GuestMemoryMmap,
}

const N_ENTRIES: usize = 4 * 4096 / std::mem::size_of::<SchedTraceEntry>();
// const N_ENTRIES: usize = 1;
impl BusDevice for SchedTracer {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        match offset {
            0 => data.copy_from_slice(&self.pid.to_le_bytes()),
            _ => info!("SchedTracer: invalid read")
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        match self.state {
            State::Init => {
                self.trace_base = u64::from_le_bytes(data.try_into().unwrap());
                self.state = State::Tracing;
                info!("sched trace base = 0x{:x}", self.trace_base);
            },
            State::Tracing => {
                info!("got write from guest tsc = {}", unsafe { _rdtsc() });
                let overhead = u64::from_le_bytes(data.try_into().unwrap());
                // let addr = GuestAddress(self.trace_base);
                // let mut comm = [0u8; TASK_COMM_LEN];
                // self.mem.read_slice(&mut comm, addr);
                // let comm_str = String::from_utf8_lossy(&comm.to_vec()).to_string();
                // info!("guest write pid {} comm {} tsc {}", pid, comm_str, unsafe { _rdtsc() });
                self.overhead = overhead;
                for i in 0..N_ENTRIES {
                    let addr = self.trace_base +
                        (i * std::mem::size_of::<SchedTraceEntry>()) as u64;
                    let mut entry: SchedTraceEntry =
                        self.mem.read_obj(GuestAddress(addr)).unwrap();

                    // if self.tsc_start == 0 {
                    //     self.tsc_start = unsafe { _rdtsc() } - entry.tsc;
                    //     info!("tsc offset = {}", self.tsc_start);
                    // }

                    if entry.tsc == 0 {
                        info!("tsc = 0");
                        break;
                    }

                    entry.tsc += self.tsc_start;
                    // entry.tsc = unsafe { _rdtsc() };
                    self.trace.push(entry);
                }

                // self.tsc_start = 0;

                if self.done_tracing {
                    for ent in self.trace.drain(..) {
                        info!("comm={} tsc={}",
                              String::from_utf8_lossy(&ent.comm.to_vec()).to_string(),
                              ent.tsc);
                    }
                    info!("overhead = {}ns", self.overhead);
                    self.done_tracing = false;
                }
            },
        }
        // let mut bytes = [0u8; 2];
        // bytes.copy_from_slice(data);
        // error!("guest write pid {} tsc {}", u16::from_le_bytes(bytes),
        //       unsafe { _rdtsc() });
    }

    fn interrupt(&self, irq_mask: u32) -> std::io::Result<()> {
        info!("SENDING INTERRUPT");
        self.interrupt_evt.write(1)
    }
}


impl SchedTracer {
    pub fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    pub fn set_pid(&mut self, pid: u16) {
        self.pid = pid;
    }

    pub fn start_trace(&mut self, pid: u16) {
        self.pid = pid;
        info!("sending interrupt: tsc {}", unsafe { _rdtsc() });
        self.interrupt(0).unwrap();
    }

    pub fn end_trace(&mut self, pid: u16) {
        self.pid = pid;
        info!("sending interrupt to end trace: tsc {}", unsafe { _rdtsc() });
        self.interrupt(0).unwrap();
        self.done_tracing = true;
    }

    pub fn new(mem: GuestMemoryMmap, pid: u16) -> Self {
        SchedTracer {
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            pid,
            mem,
            trace_base: 0,
            state: State::Init,
            trace: Vec::new(),
            done_tracing: false,
            overhead: 0,
            tsc_start: 0,
        }
    }
}

impl Persist<'_> for SchedTracer {
    type State = SchedTracerState;
    type ConstructorArgs = SchedTracerConstructorArgs;
    type Error = ();
    fn save (&self) -> Self::State {
        SchedTracerState {
            pid: self.pid,
            trace_base: self.trace_base,
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        let mut tracer = Self::new(constructor_args.mem, state.pid);
        tracer.trace_base = state.trace_base;
        tracer.state = State::Tracing;
        info!("sched trace base = 0x{:x}", tracer.trace_base);
        Ok(tracer)
    }
}
