use std::{
    arch::x86_64::__cpuid,
    convert::TryInto,
    fmt::Display,
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom},
    os::unix::prelude::AsRawFd,
    path::PathBuf,
    sync::Arc,
};

use kvm_bindings::{
    kvm_sev_cmd, kvm_sev_launch_measure, kvm_sev_launch_start, kvm_sev_launch_update_data,
    sev_cmd_id_KVM_SEV_INIT, sev_cmd_id_KVM_SEV_LAUNCH_FINISH, sev_cmd_id_KVM_SEV_LAUNCH_MEASURE,
    sev_cmd_id_KVM_SEV_LAUNCH_START, sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_DATA,
};
use kvm_ioctls::VmFd;
use logger::info;
use thiserror::Error;
use utils::time::TimestampUs;
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

/// Length of intial boot time measurement
const MEASUREMENT_LEN: u32 = 48;
/// Where the SEV firmware will be loaded in guest memory
pub const FIRMWARE_ADDR: GuestAddress = GuestAddress(0x100000);
/// Default guest policy (disable debug)
const DEFAULT_POLICY: u32 = 1;

//This excludes SUCCESS=0 and ACTIVE=18
#[derive(Debug, Error)]
/// SEV platform errors
pub enum SevError {
    /// The platform state is invalid for this command
    InvalidPlatformState,
    /// The guest state is invalid for this command
    InvalidGuestState,
    /// The platform configuration is invalid
    InvalidConfig,
    /// A memory buffer is too small
    InvalidLength,
    /// The platform is already owned
    AlreadyOwned,
    /// The certificate is invalid
    InvalidCertificate,
    /// Request is not allowed by guest policy
    PolicyFailure,
    /// The guest is inactive
    Inactive,
    /// The address provided is inactive
    InvalidAddress,
    /// The provided signature is invalid
    BadSignature,
    /// The provided measurement is invalid
    BadMeasurement,
    /// The ASID is already owned
    AsidOwned,
    /// The ASID is invalid
    InvalidAsid,
    /// WBINVD instruction required
    WBINVDRequired,
    ///DF_FLUSH invocation required
    DfFlushRequired,
    /// The guest handle is invalid
    InvalidGuest,
    /// The command issued is invalid
    InvalidCommand,
    /// The error code returned by the SEV device is not valid
    InvalidErrorCode,
    /// Other error code
    Errno(i32),
}
#[derive(Debug)]
/// Temp
pub enum Error {
    /// Error loading SEV firmware
    FirmwareLoad,
}

impl Display for SevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<u32> for SevError {
    fn from(code: u32) -> Self {
        match code {
            1 => Self::InvalidPlatformState,
            2 => Self::InvalidGuestState,
            3 => Self::InvalidConfig,
            4 => Self::InvalidLength,
            5 => Self::AlreadyOwned,
            6 => Self::InvalidCertificate,
            7 => Self::PolicyFailure,
            8 => Self::Inactive,
            9 => Self::InvalidAddress,
            10 => Self::BadSignature,
            11 => Self::BadMeasurement,
            12 => Self::AsidOwned,
            13 => Self::InvalidAsid,
            14 => Self::WBINVDRequired,
            15 => Self::DfFlushRequired,
            16 => Self::InvalidGuest,
            17 => Self::InvalidCommand,
            _ => Self::InvalidErrorCode,
        }
    }
}

/// SEV result return type
pub type SevResult<T> = std::result::Result<T, SevError>;
/// SEV Guest states
#[derive(PartialEq)]
pub enum State {
    /// The guest is uninitialized
    UnInit,
    /// The SEV platform has been initialized
    Init,
    /// The guest is currently beign launched and plaintext data and VMCB save areas are being imported
    LaunchUpdate,
    /// The guest is currently being launched and ciphertext data are being imported
    LaunchSecret,
    /// The guest is fully launched or migrated in, and not being migrated out to another machine
    Running,
    /// The guest is currently being migrated out to another machine
    SendUpdate,
    /// The guest is currently being migrated from another machine
    RecieveUpdate,
    /// The guest has been sent to another machine
    Sent,
}
/// Struct to hold SEV info
pub struct Sev {
    fd: File,
    vm_fd: Arc<VmFd>,
    handle: u32,
    policy: u32,
    state: State,
    measure: Vec<u8>,
    timestamp: TimestampUs, 
    /// position of the Cbit
    pub cbitpos: u32,
    /// DEBUG whether or not encryption is active. This is for testing the firmware without encryption
    pub encryption: bool,
    // kernel_len: u32,
}

impl Sev {
    ///Initialize SEV
    pub fn new(vm_fd: Arc<VmFd>, encryption: bool, timestamp: TimestampUs) -> Self {
        //Open /dev/sev

        info!("Creating SEV device: policy 0x{:x}", DEFAULT_POLICY);

        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sev")
            .unwrap();

        let ebx;

        //Get position of the C-bit
        unsafe {
            ebx = __cpuid(0x8000001F).ebx & 0x3f;
        }

        Sev {
            fd: fd,
            vm_fd: vm_fd,
            handle: 0,
            policy: DEFAULT_POLICY,
            state: State::UnInit,
            measure: Vec::with_capacity(48),
            cbitpos: ebx,
            encryption: encryption,
            timestamp,
        }
    }

    fn sev_ioctl(&mut self, cmd: &mut kvm_sev_cmd) -> SevResult<()> {
        match self.vm_fd.encrypt_op_sev(cmd) {
            Err(err) => {
                if cmd.error > 0 {
                    return Err(SevError::from(cmd.error));
                } else {
                    return Err(SevError::Errno(err.errno()));
                }
            }
            _ => Ok(()),
        }
    }

    /// Initialize SEV platform
    pub fn sev_init(&mut self) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }
        info!("Sending SEV_INIT");

        if self.state != State::UnInit {
            return Err(SevError::InvalidPlatformState);
        }
        let mut init = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_INIT,
            data: 0,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut init).unwrap();

        self.state = State::Init;
        info!("Done Sending SEV_INIT");

        self.sev_launch_start()
    }
    /// Get SEV guest handle
    fn sev_launch_start(&mut self) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }
        info!("LAUNCH_START");

        if self.state != State::Init {
            return Err(SevError::InvalidPlatformState);
        }

        let start = kvm_sev_launch_start {
            handle: 0,
            policy: self.policy,
            //The remaining 4 fields are optional but should be explored later
            ..Default::default()
        };

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_START,
            data: &start as *const kvm_sev_launch_start as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.handle = start.handle;
        self.state = State::LaunchUpdate;
        info!("LAUNCH_START Done");
        Ok(())
    }

    /// Encrypt region
    pub fn launch_update_data(&mut self, mut addr: u64, mut len: u32) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }

        if addr % 16 != 0 {
            addr -= addr % 16;
            len += (addr % 16) as u32;
        }

        if len % 16 != 0 {
            len = len - (len % 16) + 16;
        }

        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        let region = kvm_sev_launch_update_data {
            uaddr: addr,
            len: len,
        };

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_DATA,
            data: &region as *const kvm_sev_launch_update_data as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!(
            "Pre-encryption start: {:>06} us, {:>06} CPU us",
            real, cpu
        );
        self.sev_ioctl(&mut msg).unwrap();let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!(
            "Pre-encryption done: {:>06} us, {:>06} CPU us",
            real, cpu
        );
        Ok(())
    }

    /// Get boot measurement
    pub fn get_launch_measurement(&mut self) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }
        info!("Sending LAUNCH_MEASURE");

        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        let len = MEASUREMENT_LEN;

        for _ in 0..len as usize {
            self.measure.push(0);
        }

        let mut measure: kvm_sev_launch_measure = Default::default();

        measure.uaddr = self.measure.as_ptr() as _;
        measure.len = len;

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_MEASURE,
            data: &measure as *const kvm_sev_launch_measure as u64,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.state = State::LaunchSecret;
        info!("Done Sending LAUNCH_MEASURE");

        Ok(())
    }

    /// Finish SEV launch sequence
    pub fn sev_launch_finish(&mut self) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }
        info!("Sending LAUNCH_FINISH");

        if self.state != State::LaunchSecret {
            return Err(SevError::InvalidPlatformState);
        }

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_FINISH,
            sev_fd: self.fd.as_raw_fd() as _,
            data: self.handle as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.state = State::Running;
        info!("Done Sending LAUNCH_FINISH");

        Ok(())
    }

    ///Load SEV firmware
    pub fn load_firmware(&mut self, path: &String, guest_mem: &GuestMemoryMmap) -> SevResult<()> {
        let path = PathBuf::from(path);
        let mut f_firmware = File::open(path.as_path()).unwrap();
        f_firmware.seek(SeekFrom::Start(0)).unwrap();
        let len = f_firmware.seek(SeekFrom::End(0)).unwrap();
        f_firmware.seek(SeekFrom::Start(0)).unwrap();

        guest_mem
            .read_exact_from(FIRMWARE_ADDR, &mut f_firmware, len.try_into().unwrap())
            .unwrap();

        let addr = guest_mem.get_host_address(FIRMWARE_ADDR).unwrap() as u64;

        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!(
            "Pre-encrypting firmware: {:>06} us, {:>06} CPU us",
            real, cpu
        );
        self.launch_update_data(addr, len.try_into().unwrap())?;
        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!(
            "Done pre-encrypting firmware: {:>06} us, {:>06} CPU us",
            real, cpu
        );

        Ok(())
    }
}
