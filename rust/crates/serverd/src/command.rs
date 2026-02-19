use pie_kernel_state::StateDelta;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
pub enum Mode {
    Null,
    Route,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderMode {
    Live,
    Replay,
    Record,
}

impl ProviderMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderMode::Live => "live",
            ProviderMode::Replay => "replay",
            ProviderMode::Record => "record",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "live" => Some(ProviderMode::Live),
            "replay" => Some(ProviderMode::Replay),
            "record" => Some(ProviderMode::Record),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Args {
    pub runtime_root: PathBuf,
    pub delta: StateDelta,
    pub ticks: u64,
    pub mode: Mode,
    pub skill_id: Option<String>,
    pub mode_profile: Option<String>,
    pub provider_mode: ProviderMode,
}

pub struct VerifyArgs {
    pub runtime_root: PathBuf,
    pub verify_memory: bool,
    pub run_id: Option<String>,
}

pub struct IngestArgs {
    pub runtime_root: PathBuf,
    pub source: InputSource,
}

pub struct ReplayArgs {
    pub runtime_root: PathBuf,
    pub task_id: String,
}

pub struct ApproveArgs {
    pub runtime_root: PathBuf,
    pub tool_id: String,
    pub input_ref: String,
    pub run_id: Option<String>,
}

pub struct LearnArgs {
    pub runtime_root: PathBuf,
    pub text: String,
    pub tags: Option<String>,
    pub source: Option<String>,
}

pub struct CapsuleExportArgs {
    pub runtime_root: PathBuf,
    pub run_id: String,
    pub out: Option<PathBuf>,
}

pub struct OperatorApproveArgs {
    pub runtime_root: PathBuf,
    pub run_id: String,
    pub tool_or_action_id: String,
    pub reason: String,
    pub input_ref: Option<String>,
}
pub struct OperatorRefuseArgs {
    pub runtime_root: PathBuf,
    pub run_id: String,
    pub tool_or_action_id: String,
    pub reason: String,
}

pub struct OperatorLearningsAppendArgs {
    pub runtime_root: PathBuf,
    pub skill_id: String,
    pub learning_text: String,
    pub tags: Option<String>,
}

pub struct OperatorReplayVerifyArgs {
    pub runtime_root: PathBuf,
    pub run_id: Option<String>,
    pub capsule_ref: Option<String>,
}

pub struct OperatorCapsuleExportArgs {
    pub runtime_root: PathBuf,
    pub run_id: Option<String>,
    pub capsule_ref: Option<String>,
    pub out: PathBuf,
}

#[derive(Debug, Clone)]
pub enum InputSource {
    Stdin,
    File(PathBuf),
}
