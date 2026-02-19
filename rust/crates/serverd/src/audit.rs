use crate::task::task_store::{Intent, TaskSource};
use pie_audit_log::{verify_log, AuditAppender};
use pie_kernel_state::StateDelta;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;

const AUDIT_SCHEMA: &str = "serverd.audit.v1";

#[derive(Debug, Serialize)]
struct AuditEnvelope {
    schema: &'static str,
    event: AuditEvent,
}
#[derive(Debug)]
pub(crate) struct AuditReadError {
    reason: &'static str,
    detail: Option<String>,
}

impl AuditReadError {
    pub(crate) fn new(reason: &'static str) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    pub(crate) fn with_detail(reason: &'static str, detail: String) -> Self {
        Self {
            reason,
            detail: Some(detail),
        }
    }

    pub(crate) fn reason(&self) -> &'static str {
        self.reason
    }
    pub(crate) fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl std::fmt::Display for AuditReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.detail.as_ref() {
            Some(detail) => write!(f, "{}: {}", self.reason, detail),
            None => write!(f, "{}", self.reason),
        }
    }
}

impl std::error::Error for AuditReadError {}

pub(crate) fn append_event(
    audit: &mut AuditAppender,
    event: AuditEvent,
) -> Result<String, pie_audit_log::AuditLogError> {
    let envelope = AuditEnvelope {
        schema: AUDIT_SCHEMA,
        event,
    };
    audit.append(&envelope)
}
pub(crate) fn fail_run(
    audit: &mut AuditAppender,
    audit_path: &Path,
    runtime_root: &Path,
    last_state_hash: &str,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    emit_run_error(audit, audit_path, runtime_root, last_state_hash, reason)
}

pub(crate) fn succeed_run(
    _audit: &mut AuditAppender,
    audit_path: &Path,
    payload: serde_json::Value,
    pretty: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = verify_log(audit_path)?;
    let output = if pretty {
        serde_json::to_string_pretty(&payload)?
    } else {
        serde_json::to_string(&payload)?
    };
    println!("{}", output);
    Ok(())
}
pub(crate) fn read_audit_events(audit_path: &Path) -> Result<Vec<Value>, AuditReadError> {
    let contents = fs::read_to_string(audit_path)
        .map_err(|e| AuditReadError::with_detail("audit_log_invalid", e.to_string()))?;
    let mut events = Vec::new();
    for (i, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: Value = serde_json::from_str(line).map_err(|_| {
            AuditReadError::with_detail("audit_log_invalid", format!("line {}", i + 1))
        })?;
        let envelope = record
            .get("event")
            .ok_or_else(|| AuditReadError::new("audit_log_invalid"))?;
        let inner = match envelope.get("event") {
            Some(inner) => inner,
            None => envelope,
        };
        let event_type = inner
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuditReadError::new("audit_log_invalid"))?;
        if event_type.is_empty() {
            return Err(AuditReadError::new("audit_log_invalid"));
        }
        events.push(inner.clone());
    }
    Ok(events)
}

pub(crate) fn filter_events_for_run(
    events: &[Value],
    run_id: &str,
) -> Result<Vec<Value>, AuditReadError> {
    let mut in_run = false;
    let mut selected = Vec::new();
    for event in events {
        let event_type = event
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuditReadError::new("audit_log_invalid"))?;
        if event_type == "run_started" {
            if in_run {
                return Err(AuditReadError::new("audit_log_invalid"));
            }
            let event_run_id = event
                .get("run_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AuditReadError::new("audit_log_invalid"))?;
            if event_run_id == run_id {
                in_run = true;
                selected.push(event.clone());
            }
            continue;
        }
        if !in_run {
            continue;
        }
        if event_type == "run_completed" {
            let event_run_id = event
                .get("run_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AuditReadError::new("audit_log_invalid"))?;
            if event_run_id != run_id {
                return Err(AuditReadError::new("audit_log_invalid"));
            }
            selected.push(event.clone());
            return Ok(selected);
        }
        selected.push(event.clone());
    }
    Err(AuditReadError::new("audit_log_invalid"))
}

fn latest_started_run_id(events: &[Value]) -> Result<String, AuditReadError> {
    for event in events.iter().rev() {
        let event_type = event
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuditReadError::new("audit_log_invalid"))?;
        if event_type != "run_started" {
            continue;
        }
        let run_id = event
            .get("run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuditReadError::new("audit_log_invalid"))?;
        return Ok(run_id.to_string());
    }
    Err(AuditReadError::new("audit_log_invalid"))
}

fn emit_run_error(
    audit: &mut AuditAppender,
    audit_path: &Path,
    runtime_root: &Path,
    last_state_hash: &str,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let events = read_audit_events(audit_path)?;
    let run_id = latest_started_run_id(&events)?;
    append_event(
        audit,
        AuditEvent::RunCompleted {
            run_id,
            final_state_hash: last_state_hash.to_string(),
        },
    )?;
    let _ = verify_log(audit_path)?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "ok": false,
            "error": reason,
            "runtime_root": runtime_root.to_string_lossy(),
            "audit_path": audit_path.to_string_lossy()
        }))?
    );
    Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, reason).into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Observation {
    pub(crate) tick_index: u64,
    pub(crate) observed_files: Vec<String>,
}

// Stage 0 + Stage 1 audit events
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "event_type")]
#[allow(dead_code)]
pub(crate) enum AuditEvent {
    // Stage 0 events
    RunStarted {
        run_id: String,
    },
    TickCompleted {
        tick_index: u64,
        state_hash: String,
        request_hash: String,
    },
    RunCompleted {
        run_id: String,
        final_state_hash: String,
    },

    // Stage 1 events
    ObservationCaptured {
        observation: Observation,
    },
    StateSnapshotLoaded {
        tick_index: u64,
        state_hash: String,
    },
    IntentSelected {
        intent: Intent,
        request_hash: String,
    },
    StateDeltaProposed {
        tick_index: u64,
        delta: StateDelta,
    },
    StateDeltaApplied {
        tick_index: u64,
        next_state_hash: String,
    },

    // Stage 2 events
    TaskReceived {
        source: TaskSource,
        bytes: u64,
    },
    TaskRejected {
        reason: String,
    },
    TaskAccepted {
        task_id: String,
    },

    // Stage 3 events
    TaskPersisted {
        task_id: String,
        path: String,
    },
    TaskPersistFailed {
        task_id: String,
        reason: String,
    },
    TaskReplayRequested {
        task_id: String,
    },
    TaskReplayLoaded {
        task_id: String,
    },

    // Stage 3 routing/provider events
    ProviderModeSelected {
        provider_mode: String,
        config_hash: String,
    },
    RouteSelected {
        provider_id: String,
        reason: String,
        request_hash: String,
    },
    ContextSelected {
        request_hash: String,
        context_ref: String,
    },
    ProviderRequestWritten {
        provider_id: String,
        request_hash: String,
        artifact_ref: String,
    },
    ProviderResponseWritten {
        provider_id: String,
        request_hash: String,
        artifact_ref: String,
    },
    ProviderResponseArtifactWritten {
        provider_id: String,
        request_hash: String,
        artifact_ref: String,
    },
    ProviderResponseArtifactLoaded {
        provider_id: String,
        request_hash: String,
        artifact_ref: String,
    },
    ProviderReplayMissingArtifact {
        request_hash: String,
        expected_artifact_path: String,
    },
    ProviderRecordConflict {
        request_hash: String,
        artifact_ref: String,
    },
    ProviderFailed {
        provider_id: String,
        request_hash: String,
        error: String,
    },

    // Stage 7 events
    RedactionConfigLoaded {
        config_ref: String,
        run_id: String,
    },
    ProviderInputRedacted {
        request_hash: String,
        input_ref: String,
    },

    // Stage 8 events
    ContextPolicyLoaded {
        policy_ref: String,
    },
    PromptBuilt {
        request_hash: String,
        prompt_ref: String,
        context_ref: String,
        policy_ref: String,
    },

    // Stage 13 events
    RetrievalConfigLoaded {
        config_ref: String,
    },
    RetrievalQueryWritten {
        request_hash: String,
        query_ref: String,
    },
    RetrievalExecuted {
        request_hash: String,
        results_count: u64,
        result_set_hash: String,
    },
    RetrievalResultsWritten {
        request_hash: String,
        results_ref: String,
    },
    RetrievalFailed {
        request_hash: String,
        reason: String,
    },

    // Stage 14 events
    LensConfigLoaded {
        config_ref: String,
    },
    LensPlanBuilt {
        plan_ref: String,
        plan_hash: String,
        selected_lenses: Vec<String>,
    },
    LensSetSelected {
        request_hash: String,
        lens_set_ref: String,
    },
    LensExecuted {
        request_hash: String,
        lens_id: String,
    },
    LensOutputsWritten {
        request_hash: String,
        outputs_ref: String,
    },
    LensFailed {
        request_hash: String,
        reason: String,
    },
    ModeConfigLoaded {
        config_ref: String,
    },
    ModeProfileSelected {
        mode_id: String,
        profile_ref: String,
    },
    ModeRouted {
        skill_id: String,
        mode_id: String,
        route_ref: String,
    },
    ModeApplied {
        mode_id: String,
        mode_hash: String,
    },
    ModePolicyApplied {
        mode_id: String,
        policy_hash: String,
    },
    ModeFailed {
        reason: String,
    },
    MemoryLatticeBuilt {
        lattice_ref: String,
        lattice_hash: String,
        item_count: u64,
        bytes: u64,
    },
    RepoIdentityWritten {
        root_hash: String,
        artifact_ref: String,
        file_count: u64,
        total_bytes: u64,
    },
    RepoIndexSnapshotWritten {
        root_hash: String,
        artifact_ref: String,
        chunk_count: u64,
        file_count: u64,
    },
    PortPlanRequestWritten {
        artifact_ref: String,
    },
    PortPlanWritten {
        plan_root_hash: String,
        artifact_ref: String,
        request_ref: String,
        repo_identity_root_hash: String,
        repo_index_snapshot_root_hash: String,
        node_count: u64,
        invariant_count: u64,
        work_unit_count: u64,
    },
    PortPlanSummaryWritten {
        artifact_ref: String,
    },

    // Stage 9 events
    OutputContractLoaded {
        contract_id: String,
        contract_hash: String,
    },
    ProviderOutputValidated {
        request_hash: String,
        contract_id: String,
        ok: bool,
    },
    ProviderOutputRejected {
        request_hash: String,
        contract_id: String,
        reason: String,
    },

    // Stage 10 events
    RunCapsuleWritten {
        capsule_ref: String,
        capsule_hash: String,
    },

    // Stage 11 events
    ExplainWritten {
        explain_ref: String,
        capsule_ref: String,
    },
    ExplainFailed {
        capsule_ref: String,
        reason: String,
    },

    // Stage 12 events
    WorkspacePolicyLoaded {
        policy_hash: String,
    },
    WorkspaceViolation {
        tool_id: String,
        reason: String,
        request_hash: String,
    },

    // Stage 4 events
    TaskEnqueued {
        task_id: String,
    },
    TaskClaimed {
        task_id: String,
    },
    TaskAlreadyApplied {
        task_id: String,
    },
    TaskApplied {
        task_id: String,
        state_hash: String,
    },
    ToolExecutionDenied {
        tool_id: String,
        reason: String,
        request_hash: String,
    },
    ToolApprovalRequired {
        tool_id: String,
        approval_ref: String,
        request_hash: String,
    },
    ToolSelected {
        tool_id: String,
        input_ref: String,
        request_hash: String,
    },
    ToolExecuted {
        tool_id: String,
        input_ref: String,
        output_ref: String,
        request_hash: String,
    },
    ToolOutputWritten {
        tool_id: String,
        artifact_ref: String,
        request_hash: String,
    },
    ToolCallWritten {
        tool_id: String,
        tool_call_ref: String,
        request_hash: String,
    },
    StateDeltaArtifactWritten {
        delta_ref: String,
        request_hash: String,
    },

    // Stage 15 events
    ApprovalCreated {
        tool_id: String,
        approval_ref: String,
        input_ref: String,
        request_hash: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        run_id: Option<String>,
    },
    LearningAppended {
        entry_hash: String,
        bytes_written: u64,
    },
    CapsuleExported {
        capsule_ref: String,
        export_hash: String,
        export_path: String,
    },
    OperatorActionRequested {
        action: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        run_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        target_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        target_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason_hash: Option<String>,
    },
    OperatorActionRefused {
        action: String,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        run_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        target_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        target_ref: Option<String>,
    },
    OperatorActionCompleted {
        action: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        run_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        target_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        target_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifact_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifact_hash: Option<String>,
    },

    // Stage 5 events
    SkillSelected {
        skill_id: String,
        skill_manifest_hash: String,
    },
    SkillLearningAppended {
        skill_id: String,
        entry_hash: String,
    },
    TaskQueueScanned {
        pending: u64,
    },

    // Stage 2 memory events (episodic/working/open memory)
    EpisodeAppended {
        episode_hash: String,
        artifact_refs_count: u64,
    },
    WorkingMemoryUpdated {
        keys_added: u64,
        keys_evicted: u64,
    },
    OpenMemoryMirrorWritten {
        enabled: bool,
        items: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::filter_events_for_run;
    use serde_json::json;

    #[test]
    fn filter_events_for_run_rejects_missing_run_completed_run_id() {
        let run_id = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let events = vec![
            json!({
                "event_type": "run_started",
                "run_id": run_id
            }),
            json!({
                "event_type": "run_completed",
                "final_state_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        ];
        assert!(filter_events_for_run(&events, run_id).is_err());
    }

    #[test]
    fn filter_events_for_run_rejects_mismatched_run_completed_run_id() {
        let run_id = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let events = vec![
            json!({
                "event_type": "run_started",
                "run_id": run_id
            }),
            json!({
                "event_type": "run_completed",
                "run_id": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "final_state_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        ];
        assert!(filter_events_for_run(&events, run_id).is_err());
    }

    #[test]
    fn filter_events_for_run_accepts_matching_run_completed_run_id() {
        let run_id = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let events = vec![
            json!({
                "event_type": "run_started",
                "run_id": run_id
            }),
            json!({
                "event_type": "tick_completed",
                "tick_index": 0
            }),
            json!({
                "event_type": "run_completed",
                "run_id": run_id,
                "final_state_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        ];
        let selected = filter_events_for_run(&events, run_id).expect("filter should succeed");
        assert_eq!(selected.len(), 3);
        assert_eq!(
            selected[2]
                .get("run_id")
                .and_then(|v| v.as_str())
                .expect("missing run_completed.run_id"),
            run_id
        );
    }
}
