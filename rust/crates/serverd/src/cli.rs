use crate::command::{
    ApproveArgs, Args, CapsuleExportArgs, IngestArgs, InputSource, LearnArgs, Mode,
    OperatorApproveArgs, OperatorCapsuleExportArgs, OperatorLearningsAppendArgs,
    OperatorRefuseArgs, OperatorReplayVerifyArgs, ProviderMode, ReplayArgs, VerifyArgs,
};
use crate::mutations::{run_approve, run_capsule_export, run_learn};
use crate::operator_actions::{
    run_operator_approve, run_operator_capsule_export, run_operator_learnings_append,
    run_operator_refuse, run_operator_replay_verify,
};
use crate::runner::{run_ingest, run_null, run_replay, run_route, run_verify};
use crate::runtime::explain::run_explain;
use crate::runtime::explain_args::ExplainArgs;
use pie_kernel_state::StateDelta;
use std::path::PathBuf;

pub(crate) enum Command {
    Run(Args),
    Verify(VerifyArgs),
    Ingest(IngestArgs),
    Replay(ReplayArgs),
    Explain(ExplainArgs),
    Approve(ApproveArgs),
    Learn(LearnArgs),
    CapsuleExport(CapsuleExportArgs),
    OperatorApprove(OperatorApproveArgs),
    OperatorRefuse(OperatorRefuseArgs),
    OperatorLearningsAppend(OperatorLearningsAppendArgs),
    OperatorReplayVerify(OperatorReplayVerifyArgs),
    OperatorCapsuleExport(OperatorCapsuleExportArgs),
}

fn default_runtime_root() -> PathBuf {
    // serverd crate is at: <repo>/rust/crates/serverd
    // repo root is: <repo> = three parents up
    if let Some(v) = std::env::var_os("PIE_RUNTIME_ROOT") {
        return PathBuf::from(v);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("runtime")
}

fn parse_delta_arg(v: &str) -> StateDelta {
    let v = v.trim();

    // tick:1
    if let Some(rest) = v.strip_prefix("tick:") {
        return StateDelta::TickAdvance {
            by: rest.parse().unwrap_or(1),
        };
    }

    // tag:key=value
    if let Some(rest) = v.strip_prefix("tag:") {
        if let Some((k, val)) = rest.split_once('=') {
            return StateDelta::SetTag {
                key: k.to_string(),
                value: val.to_string(),
            };
        }
    }

    // conservative default
    StateDelta::TickAdvance { by: 1 }
}

fn parse_run_args_from<I>(mut it: I) -> Result<Args, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut delta = StateDelta::TickAdvance { by: 1 };
    let mut ticks: u64 = 1;
    let mut mode = Mode::Null;
    let mut skill_id: Option<String> = None;
    let mut mode_profile: Option<String> = None;
    let mut provider_mode: Option<ProviderMode> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--delta" => {
                let v = it.next().ok_or("missing value for --delta")?;
                delta = parse_delta_arg(&v);
            }
            "--ticks" => {
                let v = it.next().ok_or("missing value for --ticks")?;
                ticks = v
                    .parse::<u64>()
                    .map_err(|_| "invalid value for --ticks".to_string())?;
            }
            "--mode" => {
                let v = it.next().ok_or("missing value for --mode")?;
                mode = match v.as_str() {
                    "null" => Mode::Null,
                    "route" => Mode::Route,
                    _ => return Err(format!("unknown mode: {}", v)),
                };
            }
            "--skill" => {
                if skill_id.is_some() {
                    return Err("multiple values provided for --skill".to_string());
                }
                let v = it.next().ok_or("missing value for --skill")?;
                skill_id = Some(v);
            }
            "--mode-profile" => {
                if mode_profile.is_some() {
                    return Err("multiple values provided for --mode-profile".to_string());
                }
                let v = it.next().ok_or("missing value for --mode-profile")?;
                mode_profile = Some(v);
            }
            "--provider" => {
                if provider_mode.is_some() {
                    return Err("multiple values provided for --provider".to_string());
                }
                let v = it.next().ok_or("missing value for --provider")?;
                provider_mode = Some(
                    ProviderMode::parse(&v)
                        .ok_or_else(|| format!("unknown provider mode: {}", v))?,
                );
            }
            _ => {}
        }
    }

    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    if skill_id.is_some() && !matches!(mode, Mode::Route) {
        return Err("flag --skill requires --mode route".to_string());
    }
    if mode_profile.is_some() && !matches!(mode, Mode::Route) {
        return Err("flag --mode-profile requires --mode route".to_string());
    }

    Ok(Args {
        runtime_root,
        delta,
        ticks,
        mode,
        skill_id,
        mode_profile,
        provider_mode: provider_mode.unwrap_or(ProviderMode::Live),
    })
}

fn parse_verify_args_from<I>(mut it: I) -> Result<VerifyArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut verify_memory = false;
    let mut run_id: Option<String> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--memory" => {
                verify_memory = true;
            }
            "--run-id" => {
                if run_id.is_some() {
                    return Err("multiple values provided for --run-id".to_string());
                }
                run_id = Some(it.next().ok_or("missing value for --run-id")?);
            }
            "--ticks" | "--delta" | "--mode" | "--skill" | "--mode-profile" => {
                return Err(format!("flag {} is not valid for verify", a));
            }
            _ => {}
        }
    }

    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    Ok(VerifyArgs {
        runtime_root,
        verify_memory,
        run_id,
    })
}

fn parse_ingest_args_from<I>(mut it: I) -> Result<IngestArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut source: Option<InputSource> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--in" => {
                if source.is_some() {
                    return Err("multiple input sources provided".to_string());
                }
                let path = it.next().ok_or("missing value for --in")?;
                source = Some(InputSource::File(PathBuf::from(path)));
            }
            "--stdin" => {
                if source.is_some() {
                    return Err("multiple input sources provided".to_string());
                }
                source = Some(InputSource::Stdin);
            }
            "--ticks" | "--delta" | "--mode" | "--skill" | "--mode-profile" => {
                return Err(format!("flag {} is not valid for ingest", a));
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }

    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    let source = source.unwrap_or(InputSource::Stdin);
    Ok(IngestArgs {
        runtime_root,
        source,
    })
}

fn parse_replay_args_from<I>(mut it: I) -> Result<ReplayArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut task_id: Option<String> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--task" => {
                task_id = Some(it.next().ok_or("missing value for --task")?);
            }
            "--ticks" | "--delta" | "--mode" | "--stdin" | "--in" | "--skill"
            | "--mode-profile" => {
                return Err(format!("flag {} is not valid for replay", a));
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }

    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    let task_id = task_id.ok_or("missing value for --task")?;
    Ok(ReplayArgs {
        runtime_root,
        task_id,
    })
}
fn parse_approve_args_from<I>(mut it: I) -> Result<ApproveArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut tool_id: Option<String> = None;
    let mut input_ref: Option<String> = None;
    let mut run_id: Option<String> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--tool" => {
                if tool_id.is_some() {
                    return Err("multiple values provided for --tool".to_string());
                }
                tool_id = Some(it.next().ok_or("missing value for --tool")?);
            }
            "--input-ref" => {
                if input_ref.is_some() {
                    return Err("multiple values provided for --input-ref".to_string());
                }
                input_ref = Some(it.next().ok_or("missing value for --input-ref")?);
            }
            "--run-id" => {
                if run_id.is_some() {
                    return Err("multiple values provided for --run-id".to_string());
                }
                run_id = Some(it.next().ok_or("missing value for --run-id")?);
            }
            "--ticks" | "--delta" | "--mode" | "--skill" | "--stdin" | "--in" | "--task"
            | "--mode-profile" => {
                return Err(format!("flag {} is not valid for approve", a));
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }
    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    let tool_id = tool_id.ok_or("missing value for --tool")?;
    let input_ref = input_ref.ok_or("missing value for --input-ref")?;
    Ok(ApproveArgs {
        runtime_root,
        tool_id,
        input_ref,
        run_id,
    })
}

fn parse_learn_args_from<I>(mut it: I) -> Result<LearnArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut text: Option<String> = None;
    let mut tags: Option<String> = None;
    let mut source: Option<String> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--text" => {
                if text.is_some() {
                    return Err("multiple values provided for --text".to_string());
                }
                text = Some(it.next().ok_or("missing value for --text")?);
            }
            "--tags" => {
                if tags.is_some() {
                    return Err("multiple values provided for --tags".to_string());
                }
                tags = Some(it.next().ok_or("missing value for --tags")?);
            }
            "--source" => {
                if source.is_some() {
                    return Err("multiple values provided for --source".to_string());
                }
                source = Some(it.next().ok_or("missing value for --source")?);
            }
            "--ticks" | "--delta" | "--mode" | "--skill" | "--stdin" | "--in" | "--task"
            | "--mode-profile" => {
                return Err(format!("flag {} is not valid for learn", a));
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }
    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    let text = text.ok_or("missing value for --text")?;
    Ok(LearnArgs {
        runtime_root,
        text,
        tags,
        source,
    })
}

fn parse_capsule_export_args_from<I>(mut it: I) -> Result<CapsuleExportArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut run_id: Option<String> = None;
    let mut out: Option<PathBuf> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--run-id" => {
                if run_id.is_some() {
                    return Err("multiple values provided for --run-id".to_string());
                }
                run_id = Some(it.next().ok_or("missing value for --run-id")?);
            }
            "--out" => {
                if out.is_some() {
                    return Err("multiple values provided for --out".to_string());
                }
                out = Some(PathBuf::from(it.next().ok_or("missing value for --out")?));
            }
            "--ticks" | "--delta" | "--mode" | "--skill" | "--stdin" | "--in" | "--task"
            | "--mode-profile" => {
                return Err(format!("flag {} is not valid for capsule export", a));
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }
    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    let run_id = run_id.ok_or("missing value for --run-id")?;
    Ok(CapsuleExportArgs {
        runtime_root,
        run_id,
        out,
    })
}

fn parse_explain_args_from<I>(mut it: I) -> Result<ExplainArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut capsule_ref: Option<String> = None;
    let mut run_id: Option<String> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--capsule" => {
                if capsule_ref.is_some() {
                    return Err("multiple values provided for --capsule".to_string());
                }
                capsule_ref = Some(it.next().ok_or("missing value for --capsule")?);
            }
            "--run" => {
                if run_id.is_some() {
                    return Err("multiple values provided for --run".to_string());
                }
                run_id = Some(it.next().ok_or("missing value for --run")?);
            }
            "--ticks" | "--delta" | "--mode" | "--skill" | "--stdin" | "--in" | "--task"
            | "--mode-profile" => {
                return Err(format!("flag {} is not valid for explain", a));
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }

    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    if capsule_ref.is_some() && run_id.is_some() {
        return Err("provide either --capsule or --run, not both".to_string());
    }
    let target = match (capsule_ref, run_id) {
        (Some(capsule_ref), None) => {
            crate::runtime::explain_args::ExplainTarget::CapsuleRef(capsule_ref)
        }
        (None, Some(run_id)) => crate::runtime::explain_args::ExplainTarget::RunId(run_id),
        (None, None) => return Err("missing value for --capsule or --run".to_string()),
        _ => return Err("invalid explain target".to_string()),
    };
    Ok(ExplainArgs {
        runtime_root,
        target,
    })
}

fn parse_operator_approve_args_from<I>(mut it: I) -> Result<OperatorApproveArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut run_id: Option<String> = None;
    let mut tool_id: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut input_ref: Option<String> = None;

    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--run-id" => {
                if run_id.is_some() {
                    return Err("multiple values provided for --run-id".to_string());
                }
                run_id = Some(it.next().ok_or("missing value for --run-id")?);
            }
            "--tool-id" => {
                if tool_id.is_some() {
                    return Err("multiple values provided for --tool-id".to_string());
                }
                tool_id = Some(it.next().ok_or("missing value for --tool-id")?);
            }
            "--reason" => {
                if reason.is_some() {
                    return Err("multiple values provided for --reason".to_string());
                }
                reason = Some(it.next().ok_or("missing value for --reason")?);
            }
            "--input-ref" => {
                if input_ref.is_some() {
                    return Err("multiple values provided for --input-ref".to_string());
                }
                input_ref = Some(it.next().ok_or("missing value for --input-ref")?);
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }
    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    let run_id = run_id.ok_or("missing value for --run-id")?;
    let tool_id = tool_id.ok_or("missing value for --tool-id")?;
    let reason = reason.ok_or("missing value for --reason")?;
    Ok(OperatorApproveArgs {
        runtime_root,
        run_id,
        tool_or_action_id: tool_id,
        reason,
        input_ref,
    })
}
fn parse_operator_refuse_args_from<I>(mut it: I) -> Result<OperatorRefuseArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut run_id: Option<String> = None;
    let mut tool_id: Option<String> = None;
    let mut reason: Option<String> = None;

    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--run-id" => {
                if run_id.is_some() {
                    return Err("multiple values provided for --run-id".to_string());
                }
                run_id = Some(it.next().ok_or("missing value for --run-id")?);
            }
            "--tool-id" => {
                if tool_id.is_some() {
                    return Err("multiple values provided for --tool-id".to_string());
                }
                tool_id = Some(it.next().ok_or("missing value for --tool-id")?);
            }
            "--reason" => {
                if reason.is_some() {
                    return Err("multiple values provided for --reason".to_string());
                }
                reason = Some(it.next().ok_or("missing value for --reason")?);
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }
    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    let run_id = run_id.ok_or("missing value for --run-id")?;
    let tool_id = tool_id.ok_or("missing value for --tool-id")?;
    let reason = reason.ok_or("missing value for --reason")?;
    Ok(OperatorRefuseArgs {
        runtime_root,
        run_id,
        tool_or_action_id: tool_id,
        reason,
    })
}

fn parse_operator_learnings_append_args_from<I>(
    mut it: I,
) -> Result<OperatorLearningsAppendArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut skill_id: Option<String> = None;
    let mut learning_text: Option<String> = None;
    let mut tags: Option<String> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--skill-id" => {
                if skill_id.is_some() {
                    return Err("multiple values provided for --skill-id".to_string());
                }
                skill_id = Some(it.next().ok_or("missing value for --skill-id")?);
            }
            "--learning-text" | "--text" => {
                if learning_text.is_some() {
                    return Err("multiple values provided for --learning-text".to_string());
                }
                learning_text = Some(it.next().ok_or("missing value for --learning-text")?);
            }
            "--tags" => {
                if tags.is_some() {
                    return Err("multiple values provided for --tags".to_string());
                }
                tags = Some(it.next().ok_or("missing value for --tags")?);
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }
    let runtime_root = runtime_root.unwrap_or_else(default_runtime_root);
    let skill_id = skill_id.ok_or("missing value for --skill-id")?;
    let learning_text = learning_text.ok_or("missing value for --learning-text")?;
    Ok(OperatorLearningsAppendArgs {
        runtime_root,
        skill_id,
        learning_text,
        tags,
    })
}

fn parse_operator_replay_verify_args_from<I>(mut it: I) -> Result<OperatorReplayVerifyArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut run_id: Option<String> = None;
    let mut capsule_ref: Option<String> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--run-id" => {
                if run_id.is_some() {
                    return Err("multiple values provided for --run-id".to_string());
                }
                run_id = Some(it.next().ok_or("missing value for --run-id")?);
            }
            "--capsule-ref" | "--capsule" => {
                if capsule_ref.is_some() {
                    return Err("multiple values provided for --capsule-ref".to_string());
                }
                capsule_ref = Some(it.next().ok_or("missing value for --capsule-ref")?);
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }
    if run_id.is_some() && capsule_ref.is_some() {
        return Err("provide either --run-id or --capsule-ref, not both".to_string());
    }
    if run_id.is_none() && capsule_ref.is_none() {
        return Err("missing value for --run-id or --capsule-ref".to_string());
    }
    Ok(OperatorReplayVerifyArgs {
        runtime_root: runtime_root.unwrap_or_else(default_runtime_root),
        run_id,
        capsule_ref,
    })
}

fn parse_operator_capsule_export_args_from<I>(
    mut it: I,
) -> Result<OperatorCapsuleExportArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut runtime_root: Option<PathBuf> = None;
    let mut run_id: Option<String> = None;
    let mut capsule_ref: Option<String> = None;
    let mut out: Option<PathBuf> = None;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--runtime" => {
                runtime_root = Some(PathBuf::from(
                    it.next().ok_or("missing value for --runtime")?,
                ));
            }
            "--run-id" => {
                if run_id.is_some() {
                    return Err("multiple values provided for --run-id".to_string());
                }
                run_id = Some(it.next().ok_or("missing value for --run-id")?);
            }
            "--capsule-ref" | "--capsule" => {
                if capsule_ref.is_some() {
                    return Err("multiple values provided for --capsule-ref".to_string());
                }
                capsule_ref = Some(it.next().ok_or("missing value for --capsule-ref")?);
            }
            "--out" => {
                if out.is_some() {
                    return Err("multiple values provided for --out".to_string());
                }
                out = Some(PathBuf::from(it.next().ok_or("missing value for --out")?));
            }
            _ => {
                if a.starts_with("--") {
                    return Err(format!("unknown flag {}", a));
                }
                return Err(format!("unexpected arg {}", a));
            }
        }
    }
    if run_id.is_some() && capsule_ref.is_some() {
        return Err("provide either --run-id or --capsule-ref, not both".to_string());
    }
    if run_id.is_none() && capsule_ref.is_none() {
        return Err("missing value for --run-id or --capsule-ref".to_string());
    }
    let out = out.ok_or("missing value for --out")?;
    Ok(OperatorCapsuleExportArgs {
        runtime_root: runtime_root.unwrap_or_else(default_runtime_root),
        run_id,
        capsule_ref,
        out,
    })
}

pub(crate) fn parse_command() -> Result<Command, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(first) = args.first() {
        if first == "explain" {
            let explain_args = parse_explain_args_from(args.into_iter().skip(1))?;
            return Ok(Command::Explain(explain_args));
        }
        if first == "verify" {
            let verify_args = parse_verify_args_from(args.into_iter().skip(1))?;
            return Ok(Command::Verify(verify_args));
        }
        if first == "ingest" {
            let ingest_args = parse_ingest_args_from(args.into_iter().skip(1))?;
            return Ok(Command::Ingest(ingest_args));
        }
        if first == "replay" {
            let replay_args = parse_replay_args_from(args.into_iter().skip(1))?;
            return Ok(Command::Replay(replay_args));
        }
        if first == "approve" {
            let approve_args = parse_approve_args_from(args.into_iter().skip(1))?;
            return Ok(Command::Approve(approve_args));
        }
        if first == "learn" {
            let learn_args = parse_learn_args_from(args.into_iter().skip(1))?;
            return Ok(Command::Learn(learn_args));
        }
        if first == "capsule" {
            let sub = args.get(1).ok_or("missing capsule subcommand")?.as_str();
            match sub {
                "export" => {
                    let export_args = parse_capsule_export_args_from(args.into_iter().skip(2))?;
                    return Ok(Command::CapsuleExport(export_args));
                }
                _ => return Err(format!("unknown capsule subcommand {}", sub)),
            }
        }
        if first == "operator" {
            let sub = args.get(1).ok_or("missing operator subcommand")?.as_str();
            match sub {
                "approve" => {
                    let parsed = parse_operator_approve_args_from(args.into_iter().skip(2))?;
                    return Ok(Command::OperatorApprove(parsed));
                }
                "refuse" => {
                    let parsed = parse_operator_refuse_args_from(args.into_iter().skip(2))?;
                    return Ok(Command::OperatorRefuse(parsed));
                }
                "learnings" => {
                    let learnings_sub = args
                        .get(2)
                        .ok_or("missing operator learnings subcommand")?
                        .as_str();
                    match learnings_sub {
                        "append" => {
                            let parsed = parse_operator_learnings_append_args_from(
                                args.into_iter().skip(3),
                            )?;
                            return Ok(Command::OperatorLearningsAppend(parsed));
                        }
                        _ => {
                            return Err(format!(
                                "unknown operator learnings subcommand {}",
                                learnings_sub
                            ))
                        }
                    }
                }
                "replay-verify" => {
                    let parsed = parse_operator_replay_verify_args_from(args.into_iter().skip(2))?;
                    return Ok(Command::OperatorReplayVerify(parsed));
                }
                "capsule-export" => {
                    let parsed = parse_operator_capsule_export_args_from(args.into_iter().skip(2))?;
                    return Ok(Command::OperatorCapsuleExport(parsed));
                }
                _ => return Err(format!("unknown operator subcommand {}", sub)),
            }
        }
    }

    let run_args = parse_run_args_from(args.into_iter())?;
    Ok(Command::Run(run_args))
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let command =
        parse_command().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    match command {
        Command::Run(args) => match args.mode {
            Mode::Null => run_null(args),
            Mode::Route => run_route(args),
        },
        Command::Verify(args) => run_verify(args),
        Command::Ingest(args) => run_ingest(args),
        Command::Replay(args) => run_replay(args),
        Command::Explain(args) => run_explain(args),
        Command::Approve(args) => run_approve(args),
        Command::Learn(args) => run_learn(args),
        Command::CapsuleExport(args) => run_capsule_export(args),
        Command::OperatorApprove(args) => run_operator_approve(args),
        Command::OperatorRefuse(args) => run_operator_refuse(args),
        Command::OperatorLearningsAppend(args) => run_operator_learnings_append(args),
        Command::OperatorReplayVerify(args) => run_operator_replay_verify(args),
        Command::OperatorCapsuleExport(args) => run_operator_capsule_export(args),
    }
}
