use crate::config::supports_truecolor;
use crate::config::{MAX_PROCESS_LINES, MAX_PROCESS_OUTPUT_BYTES};
use crate::data::runtime::validate_runtime_root;
use ratatui::style::Color;
use serde_json::Value;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Child;
use std::sync::mpsc::Receiver;
use std::time::Instant;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Tab {
    Run,
    Audit,
    Artifacts,
    Capsule,
    Explain,
    Skills,
    Logs,
    Actions,
}

impl Tab {
    pub(crate) fn index(self) -> usize {
        match self {
            Tab::Run => 0,
            Tab::Audit => 1,
            Tab::Artifacts => 2,
            Tab::Capsule => 3,
            Tab::Explain => 4,
            Tab::Skills => 5,
            Tab::Logs => 6,
            Tab::Actions => 7,
        }
    }
}

pub(crate) struct Theme {
    pub(crate) accent: Color,
    pub(crate) text: Color,
}

impl Theme {
    pub(crate) fn new() -> Self {
        if supports_truecolor() {
            Self {
                accent: Color::Rgb(0xb4, 0x5a, 0x30),
                text: Color::Rgb(0x6d, 0x65, 0x60),
            }
        } else {
            Self {
                accent: Color::LightRed,
                text: Color::Gray,
            }
        }
    }
}

pub(crate) struct AuditState {
    pub(crate) path: PathBuf,
    pub(crate) events: Vec<Value>,
    pub(crate) filtered_indices: Vec<usize>,
    pub(crate) selected: usize,
    pub(crate) filter: String,
    pub(crate) offset: u64,
    pub(crate) partial: String,
    pub(crate) error_count: u64,
    pub(crate) missing: bool,
    pub(crate) error: Option<String>,
}

pub(crate) struct ArtifactEntry {
    pub(crate) display: String,
    pub(crate) path: PathBuf,
    pub(crate) is_dir: bool,
}

pub(crate) struct ArtifactState {
    pub(crate) entries: Vec<ArtifactEntry>,
    pub(crate) selected: usize,
    pub(crate) missing: bool,
    pub(crate) error: Option<String>,
}

pub(crate) struct CapsuleState {
    pub(crate) entries: Vec<PathBuf>,
    pub(crate) selected: usize,
    pub(crate) missing: bool,
    pub(crate) error: Option<String>,
}

pub(crate) struct ExplainState {
    pub(crate) entries: Vec<PathBuf>,
    pub(crate) selected: usize,
    pub(crate) missing: bool,
    pub(crate) error: Option<String>,
}

pub(crate) struct SkillEntry {
    pub(crate) id: String,
    pub(crate) manifest: Option<Value>,
    pub(crate) manifest_hash: Option<String>,
    pub(crate) error: Option<String>,
}

pub(crate) struct SkillsState {
    pub(crate) entries: Vec<SkillEntry>,
    pub(crate) selected: usize,
    pub(crate) missing: bool,
    pub(crate) error: Option<String>,
}

pub(crate) struct LogsState {
    pub(crate) entries: Vec<PathBuf>,
    pub(crate) selected: usize,
    pub(crate) missing: bool,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RunFocus {
    Skill,
    Mode,
    Delta,
    Launch,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum LogsFocus {
    Process,
    Files,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionsFocus {
    ApproveTool,
    ApproveInput,
    ApproveRunId,
    ApproveSubmit,
    LearnText,
    LearnTags,
    LearnSource,
    LearnSubmit,
    VerifyRunId,
    VerifySubmit,
    ReplayRunId,
    ReplaySubmit,
    ExportRunId,
    ExportOut,
    ExportSubmit,
}

pub(crate) struct RunState {
    pub(crate) skill_ids: Vec<String>,
    pub(crate) skill_selected: usize,
    pub(crate) mode_selected: usize,
    pub(crate) delta_input: String,
    pub(crate) focus: RunFocus,
    pub(crate) error: Option<String>,
}

pub(crate) struct ActionsState {
    pub(crate) focus: ActionsFocus,
    pub(crate) selected_action: usize,
    pub(crate) approve_tool_id: String,
    pub(crate) approve_input_ref: String,
    pub(crate) approve_run_id: String,
    pub(crate) learn_text: String,
    pub(crate) learn_tags: String,
    pub(crate) learn_source: String,
    pub(crate) verify_run_id: String,
    pub(crate) replay_run_id: String,
    pub(crate) export_run_id: String,
    pub(crate) export_out: String,
    pub(crate) error: Option<String>,
    pub(crate) last_action: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum StreamKind {
    Stdout,
    Stderr,
}

pub(crate) struct LogLine {
    pub(crate) stream: StreamKind,
    pub(crate) line: String,
}

pub(crate) struct RingBuffer {
    pub(crate) lines: VecDeque<String>,
    pub(crate) max_bytes: usize,
    pub(crate) max_lines: usize,
    pub(crate) bytes: usize,
    pub(crate) dropped: usize,
}

impl RingBuffer {
    pub(crate) fn new(max_bytes: usize, max_lines: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            max_bytes,
            max_lines,
            bytes: 0,
            dropped: 0,
        }
    }

    pub(crate) fn push(&mut self, mut line: String) {
        let mut line_bytes = line.len() + 1;
        if line_bytes > self.max_bytes {
            line = line.chars().take(self.max_bytes).collect();
            line_bytes = line.len();
            self.dropped += 1;
        }
        while !self.lines.is_empty()
            && (self.bytes + line_bytes > self.max_bytes || self.lines.len() >= self.max_lines)
        {
            if let Some(front) = self.lines.pop_front() {
                self.bytes = self.bytes.saturating_sub(front.len() + 1);
                self.dropped += 1;
            }
        }
        self.bytes += line_bytes;
        self.lines.push_back(line);
    }

    pub(crate) fn dropped(&self) -> usize {
        self.dropped
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub(crate) fn lines(&self) -> impl Iterator<Item = &String> {
        self.lines.iter()
    }
}

pub(crate) struct ProcessState {
    pub(crate) child: Option<Child>,
    pub(crate) receiver: Option<Receiver<LogLine>>,
    pub(crate) running: bool,
    pub(crate) pid: Option<u32>,
    pub(crate) start_time: Option<Instant>,
    pub(crate) exit_status: Option<i32>,
    pub(crate) output: RingBuffer,
    pub(crate) current_run_id: Option<String>,
}

pub(crate) struct App {
    pub(crate) runtime_root: PathBuf,
    pub(crate) skills_dir: Option<PathBuf>,
    pub(crate) runtime_valid: bool,
    pub(crate) runtime_error: Option<String>,
    pub(crate) active_tab: Tab,
    pub(crate) run: RunState,
    pub(crate) actions: ActionsState,
    pub(crate) audit: AuditState,
    pub(crate) artifacts: ArtifactState,
    pub(crate) capsule: CapsuleState,
    pub(crate) explain: ExplainState,
    pub(crate) skills: SkillsState,
    pub(crate) logs: LogsState,
    pub(crate) logs_focus: LogsFocus,
    pub(crate) logs_process_scroll: usize,
    pub(crate) logs_file_scroll: usize,
    pub(crate) logs_process_height: usize,
    pub(crate) logs_file_height: usize,
    pub(crate) process: ProcessState,
    pub(crate) follow_audit: bool,
    pub(crate) filter_mode: bool,
    pub(crate) filter_input: String,
    pub(crate) manual_refresh: bool,
    pub(crate) should_quit: bool,
    pub(crate) detail_scrolls: [usize; 8],
    pub(crate) list_offsets: [usize; 8],
    pub(crate) detail_heights: [usize; 8],
}

impl App {
    pub(crate) fn new(runtime_root: PathBuf, skills_dir: Option<PathBuf>) -> Self {
        let runtime_valid = validate_runtime_root(&runtime_root).is_ok();
        let runtime_error = validate_runtime_root(&runtime_root).err();
        let audit_path = runtime_root.join("logs").join("audit_rust.jsonl");
        Self {
            runtime_root,
            skills_dir,
            runtime_valid,
            runtime_error,
            active_tab: Tab::Audit,
            run: RunState {
                skill_ids: Vec::new(),
                skill_selected: 0,
                mode_selected: 0,
                delta_input: "tick:1".to_string(),
                focus: RunFocus::Skill,
                error: None,
            },
            actions: ActionsState {
                focus: ActionsFocus::ApproveTool,
                selected_action: 0,
                approve_tool_id: String::new(),
                approve_input_ref: String::new(),
                approve_run_id: String::new(),
                learn_text: String::new(),
                learn_tags: String::new(),
                learn_source: String::new(),
                verify_run_id: String::new(),
                replay_run_id: String::new(),
                export_run_id: String::new(),
                export_out: String::new(),
                error: None,
                last_action: None,
            },
            audit: AuditState {
                path: audit_path,
                events: Vec::new(),
                filtered_indices: Vec::new(),
                selected: 0,
                filter: String::new(),
                offset: 0,
                partial: String::new(),
                error_count: 0,
                missing: false,
                error: None,
            },
            artifacts: ArtifactState {
                entries: Vec::new(),
                selected: 0,
                missing: false,
                error: None,
            },
            capsule: CapsuleState {
                entries: Vec::new(),
                selected: 0,
                missing: false,
                error: None,
            },
            explain: ExplainState {
                entries: Vec::new(),
                selected: 0,
                missing: false,
                error: None,
            },
            skills: SkillsState {
                entries: Vec::new(),
                selected: 0,
                missing: false,
                error: None,
            },
            logs: LogsState {
                entries: Vec::new(),
                selected: 0,
                missing: false,
                error: None,
            },
            logs_focus: LogsFocus::Files,
            logs_process_scroll: 0,
            logs_file_scroll: 0,
            logs_process_height: 0,
            logs_file_height: 0,
            process: ProcessState {
                child: None,
                receiver: None,
                running: false,
                pid: None,
                start_time: None,
                exit_status: None,
                output: RingBuffer::new(MAX_PROCESS_OUTPUT_BYTES, MAX_PROCESS_LINES),
                current_run_id: None,
            },
            follow_audit: false,
            filter_mode: false,
            filter_input: String::new(),
            manual_refresh: false,
            should_quit: false,
            detail_scrolls: [0; 8],
            list_offsets: [0; 8],
            detail_heights: [0; 8],
        }
    }
}
