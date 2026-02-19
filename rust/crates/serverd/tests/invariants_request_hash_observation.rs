#![cfg(feature = "bin")]

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use uuid::Uuid;
mod common;

fn run_serverd_route(runtime_root: &Path) -> Output {
    Command::new(common::serverd_exe())
        .arg("--mode")
        .arg("route")
        .arg("--ticks")
        .arg("1")
        .arg("--delta")
        .arg("tick:0")
        .arg("--provider")
        .arg("live")
        .arg("--runtime")
        .arg(runtime_root.to_string_lossy().to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run serverd route")
}

fn setup_runtime(runtime_root: &Path) {
    common::write_initial_state(runtime_root);
}

fn find_request_hash(runtime_root: &Path) -> String {
    let events = common::read_event_payloads(runtime_root);
    for event in events {
        if event.get("event_type").and_then(|v| v.as_str()) == Some("provider_request_written") {
            return event
                .get("request_hash")
                .and_then(|v| v.as_str())
                .expect("provider_request_written.request_hash")
                .to_string();
        }
    }
    panic!("missing provider_request_written event");
}

#[test]
fn request_hash_ignores_generated_artifact_dirs() {
    let runtime_one = std::env::temp_dir().join(format!("pie_obs_req_hash_one_{}", Uuid::new_v4()));
    let runtime_two = std::env::temp_dir().join(format!("pie_obs_req_hash_two_{}", Uuid::new_v4()));
    setup_runtime(&runtime_one);
    setup_runtime(&runtime_two);

    fs::create_dir_all(runtime_two.join("artifacts").join("tool_outputs"))
        .expect("create tool_outputs dir");
    fs::create_dir_all(runtime_two.join("artifacts").join("provider_responses"))
        .expect("create provider_responses dir");
    fs::create_dir_all(runtime_two.join("logs")).expect("create logs dir");
    fs::write(
        runtime_two
            .join("artifacts")
            .join("tool_outputs")
            .join("seed.json"),
        b"{\"seed\":true}",
    )
    .expect("write seeded tool_outputs artifact");
    fs::write(
        runtime_two
            .join("artifacts")
            .join("provider_responses")
            .join("seed.json"),
        b"{\"seed\":true}",
    )
    .expect("write seeded provider_responses artifact");
    fs::write(runtime_two.join("logs").join("seed.log"), b"seed").expect("write seeded log file");

    let run_one = run_serverd_route(&runtime_one);
    let run_two = run_serverd_route(&runtime_two);
    assert!(
        run_one.status.success(),
        "runtime one failed: {}",
        String::from_utf8_lossy(&run_one.stderr)
    );
    assert!(
        run_two.status.success(),
        "runtime two failed: {}",
        String::from_utf8_lossy(&run_two.stderr)
    );

    let request_hash_one = find_request_hash(&runtime_one);
    let request_hash_two = find_request_hash(&runtime_two);
    assert_eq!(request_hash_one, request_hash_two);
}
