use crate::config::{MAX_PROCESS_LINES, MAX_PROCESS_OUTPUT_BYTES};
use crate::model::{App, LogLine, RingBuffer, StreamKind};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) fn resolve_serverd_binary(
    configured: Option<&PathBuf>,
) -> Result<PathBuf, Vec<PathBuf>> {
    let mut attempted = Vec::new();
    // A) Explicit CLI override (always wins)
    if let Some(path) = configured {
        attempted.push(path.clone());
        if path.is_file() {
            return Ok(path.clone());
        }
        return Err(attempted);
    }
    // B) Cargo-provided binary path
    if let Some(bin) = option_env!("CARGO_BIN_EXE_serverd") {
        let path = PathBuf::from(bin);
        attempted.push(path.clone());
        return Ok(path);
    }
    // C) PATH fallback (no which; let spawn fail if missing)
    attempted.push(PathBuf::from("serverd"));
    Ok(PathBuf::from("serverd"))
}

pub(crate) fn run_serverd_operator(app: &App, args: &[&str]) -> Result<Value, String> {
    let binary = resolve_serverd_binary(app.serverd_bin.as_ref()).map_err(|attempted| {
        let mut message = String::from("serverd binary not found. attempted paths:");
        for path in attempted {
            message.push_str(&format!("\n - {}", path.display()));
        }
        message
    })?;
    let mut command = Command::new(binary);
    command
        .arg("operator")
        .args(args)
        .arg("--runtime")
        .arg(&app.runtime_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .map_err(|e| format!("failed to spawn serverd operator: {}", e))?;
    let stdout_trimmed = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr_trimmed = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| {
        format!(
            "operator stdout is not valid json: {}",
            truncate(&stdout_trimmed)
        )
    })?;
    if output.status.success() {
        return Ok(value);
    }
    let reason = value
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("operator_command_failed");
    Err(format!(
        "{} | stderr: {}",
        reason,
        truncate(&stderr_trimmed)
    ))
}

fn truncate(value: &str) -> String {
    let max = 240;
    if value.is_empty() {
        return "(empty)".to_string();
    }
    let mut iter = value.chars();
    let prefix: String = iter.by_ref().take(max).collect();
    if iter.next().is_some() {
        format!("{}...", prefix)
    } else {
        prefix
    }
}

pub(crate) fn extract_run_id(line: &str) -> Option<String> {
    let value: Value = serde_json::from_str(line).ok()?;
    value
        .get("run_id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .or_else(|| {
            value
                .get("event")
                .and_then(|v| v.get("run_id"))
                .and_then(|v| v.as_str())
                .map(|v| v.to_string())
        })
}

pub(crate) fn handle_log_line(process: &mut crate::model::ProcessState, line: LogLine) {
    if matches!(line.stream, StreamKind::Stdout) && process.current_run_id.is_none() {
        if let Some(run_id) = extract_run_id(&line.line) {
            process.current_run_id = Some(run_id);
        }
    }
    let prefix = match line.stream {
        StreamKind::Stdout => "out",
        StreamKind::Stderr => "err",
    };
    process.output.push(format!("[{}] {}", prefix, line.line));
}

pub(crate) fn spawn_reader_thread<R: Read + Send + 'static>(
    reader: R,
    sender: Sender<LogLine>,
    kind: StreamKind,
) {
    let _ = thread::Builder::new()
        .name(match kind {
            StreamKind::Stdout => "serverd-stdout".to_string(),
            StreamKind::Stderr => "serverd-stderr".to_string(),
        })
        .spawn(move || {
            let buf_reader = BufReader::new(reader);
            for line in buf_reader.lines() {
                match line {
                    Ok(line) => {
                        let _ = sender.send(LogLine { stream: kind, line });
                    }
                    Err(_) => break,
                }
            }
        });
}

pub(crate) fn launch_serverd(app: &mut App) {
    if app.process.running {
        app.run.error = Some("serverd already running".to_string());
        return;
    }
    app.run.error = None;
    app.process.exit_status = None;
    app.process.current_run_id = None;
    app.process.output = RingBuffer::new(MAX_PROCESS_OUTPUT_BYTES, MAX_PROCESS_LINES);

    let binary = match resolve_serverd_binary(app.serverd_bin.as_ref()) {
        Ok(path) => path,
        Err(attempted) => {
            let mut message = String::from("serverd binary not found. attempted paths:");
            for path in attempted {
                message.push_str(&format!("\n - {}", path.display()));
            }
            message.push_str("\nTip: set --serverd-bin or ensure `serverd` is on PATH");
            app.run.error = Some(message);
            return;
        }
    };

    let delta = app.run.delta_input.trim();
    if delta.is_empty() {
        app.run.error = Some("delta input is required".to_string());
        return;
    }

    let modes = ["null", "route"];
    let mode = modes.get(app.run.mode_selected).copied().unwrap_or("null");

    if mode == "route" && app.run.skill_ids.is_empty() {
        app.run.error = Some("mode route requires a skill (none available)".to_string());
        return;
    }

    let mut cmd = Command::new(&binary);
    cmd.arg("--runtime")
        .arg(&app.runtime_root)
        .arg("--mode")
        .arg(mode)
        .arg("--delta")
        .arg(delta)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if mode == "route" {
        if let Some(skill) = app.run.skill_ids.get(app.run.skill_selected) {
            cmd.arg("--skill").arg(skill);
        }
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            app.run.error = Some(format!("failed to spawn serverd: {}", err));
            return;
        }
    };

    let (sender, receiver) = mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        spawn_reader_thread(stdout, sender.clone(), StreamKind::Stdout);
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_reader_thread(stderr, sender.clone(), StreamKind::Stderr);
    }

    app.process.pid = Some(child.id());
    app.process.start_time = Some(Instant::now());
    app.process.child = Some(child);
    app.process.receiver = Some(receiver);
    app.process.running = true;
    app.follow_audit = true;
}

pub(crate) fn stop_process(app: &mut App) {
    if let Some(mut child) = app.process.child.take() {
        terminate_child(&mut child);
    }
    app.process.running = false;
    app.process.pid = None;
    app.process.start_time = None;
    app.process.receiver = None;
}

pub(crate) fn terminate_child(child: &mut Child) {
    if let Ok(Some(_)) = child.try_wait() {
        return;
    }
    let pid = child.id();
    if send_sigterm(pid) {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
pub(crate) fn send_sigterm(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, libc::SIGTERM) == 0 }
}

#[cfg(not(unix))]
pub(crate) fn send_sigterm(_pid: u32) -> bool {
    false
}
