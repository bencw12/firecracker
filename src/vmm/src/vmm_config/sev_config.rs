use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
/// SEV configuration struct
pub struct SevConfig {
    /// Path to SEV firmware
    pub firmware_path: String,
    /// Path to hashes
    pub hashes_path: String,
    /// Whether or not to enable encryption
    pub encryption: bool,
    /// Guest policy
    pub policy: u32,
}
