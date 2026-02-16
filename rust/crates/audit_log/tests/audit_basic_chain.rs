use pie_audit_log::{verify_log, AuditAppender, AuditRecord};
use pie_common::{canonical_json_bytes, sha256_bytes};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{env, fs};

#[derive(Serialize)]
#[serde(rename_all = "snake_case", tag = "event_type")]
enum Ev {
    RunStarted,
    TickCompleted,
    RunCompleted,
}

#[test]
fn chains_and_verifies() {
    let p = env::temp_dir().join("pie_audit_basic_chain.jsonl");
    let _ = fs::remove_file(&p);

    let mut a = AuditAppender::open(&p).unwrap();
    a.append(&Ev::RunStarted).unwrap();
    a.append(&Ev::TickCompleted).unwrap();
    a.append(&Ev::RunCompleted).unwrap();

    let last = verify_log(&p).unwrap();
    assert!(last.starts_with("sha256:"));
}

#[test]
fn canonical_order_invariant_hashing() {
    let p1 = env::temp_dir().join("pie_audit_order_1.jsonl");
    let p2 = env::temp_dir().join("pie_audit_order_2.jsonl");
    let _ = fs::remove_file(&p1);
    let _ = fs::remove_file(&p2);

    let mut map1 = Map::new();
    map1.insert("a".to_string(), Value::from(1));
    map1.insert("b".to_string(), Value::from(2));
    let event1 = Value::Object(map1);

    let mut map2 = Map::new();
    map2.insert("b".to_string(), Value::from(2));
    map2.insert("a".to_string(), Value::from(1));
    let event2 = Value::Object(map2);

    let mut a1 = AuditAppender::open(&p1).unwrap();
    a1.append(&event1).unwrap();
    let mut a2 = AuditAppender::open(&p2).unwrap();
    a2.append(&event2).unwrap();

    let line1 = fs::read_to_string(&p1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    let line2 = fs::read_to_string(&p2)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();

    let rec1: AuditRecord = serde_json::from_str(&line1).unwrap();
    let rec2: AuditRecord = serde_json::from_str(&line2).unwrap();

    let payload1 = serde_json::json!({
        "prev_hash": "sha256:",
        "event": event1
    });
    let payload2 = serde_json::json!({
        "prev_hash": "sha256:",
        "event": event2
    });

    let bytes1 = canonical_json_bytes(&payload1).unwrap();
    let bytes2 = canonical_json_bytes(&payload2).unwrap();
    assert_eq!(bytes1, bytes2);

    let expected_hash = sha256_bytes(&bytes1);
    assert_eq!(rec1.hash, expected_hash);
    assert_eq!(rec2.hash, expected_hash);
}

#[test]
fn verify_v1_log_still_verifies() {
    let p = env::temp_dir().join("pie_audit_v1_fixture.jsonl");
    let _ = fs::remove_file(&p);

    let fixture = "\
{\"prev_hash\":\"sha256:\",\"hash\":\"sha256:050174e4332f7db751a3e987790768700d74232186c8c53c04fe1ef81ff1114a\",\"event\":{\"event_type\":\"run_started\"}}\n\
{\"prev_hash\":\"sha256:050174e4332f7db751a3e987790768700d74232186c8c53c04fe1ef81ff1114a\",\"hash\":\"sha256:119ab106f166f9808be14b6d8916e4aac1b5452d114bf6c370a1d5c04d582d86\",\"event\":{\"event_type\":\"tick_completed\"}}\n\
{\"prev_hash\":\"sha256:119ab106f166f9808be14b6d8916e4aac1b5452d114bf6c370a1d5c04d582d86\",\"hash\":\"sha256:263b199aa108271d1c9b592374829af751cd66058616673f41afa65d7e7539ee\",\"event\":{\"event_type\":\"run_completed\"}}\n";

    fs::write(&p, fixture).unwrap();

    let last = verify_log(&p).unwrap();
    assert_eq!(
        last,
        "sha256:263b199aa108271d1c9b592374829af751cd66058616673f41afa65d7e7539ee"
    );
}

#[test]
fn new_logs_are_v2() {
    let p = env::temp_dir().join("pie_audit_new_v2.jsonl");
    let _ = fs::remove_file(&p);

    let mut a = AuditAppender::open(&p).unwrap();
    a.append(&Ev::RunStarted).unwrap();

    let line = fs::read_to_string(&p)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    let rec: AuditRecord = serde_json::from_str(&line).unwrap();
    assert_eq!(rec.algo_version, 2);
}
