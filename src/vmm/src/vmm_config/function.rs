use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
/// Function command (absolute path) and args
pub struct FuncArgsConfig {
    /// command for the guest to run on boot
    pub command: String,
    /// optional arguments
    pub args: Option<String>,
}

/// Parsed FuncArgsConfig
#[derive(Debug, Clone, Serialize)]
pub struct FuncArgs {
    /// command for the guest to run on boot
    pub command: String,
    /// optional arguments
    pub args: Option<String>,
}

impl FuncArgs {
    /// Constructs FuncArgs from FuncArgsConfig
    pub fn new(cfg: &FuncArgsConfig) -> Self {
        // TODO: convert these into a single json string
        FuncArgs {
            command: cfg.command.clone(),
            args: cfg.args.clone(),
        }
    }
}
