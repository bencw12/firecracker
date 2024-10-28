use crate::logger::info;
use crate::vmm_config::function::FuncArgs;
use serde_json;
use utils::time::TimestampUs;

/// Pseudo device to send function name/arguments to the guest
#[derive(Debug)]
pub struct FuncArgsDevice {
    start_ts: TimestampUs,
    json_string: String,
    in_progress: bool,
}

impl FuncArgsDevice {
    pub fn new(start_ts: TimestampUs, func_args: FuncArgs) -> FuncArgsDevice {
        let json_string = serde_json::to_string(&func_args).unwrap();
        FuncArgsDevice {
            start_ts,
            json_string,
            in_progress: false,
        }
    }
    pub fn bus_write(&mut self, _offset: u64, _data: &[u8]) {
        self.in_progress = false;

        let now_tm_us = TimestampUs::default();
        let func_time_us = now_tm_us.time_us - self.start_ts.time_us;
        info!("func time = {:>6} us", func_time_us);
    }

    pub fn bus_read(&mut self, offset: u64, data: &mut [u8]) {
        if offset >= self.json_string.len() as u64 {
            let zeros = vec![0u8; data.len()];
            data.copy_from_slice(&zeros);
            return;
        }

        let mut n = 0;
        for c in self.json_string.as_bytes()[offset as usize..].iter() {
            data[n] = *c;
            n += 1;
            if n == data.len() {
                return;
            }
        }

        if n < data.len() {
            let zeros = vec![0u8; data.len() - n];
            data[n..].copy_from_slice(&zeros);
        }

        self.start_ts = TimestampUs::default();
    }
}
