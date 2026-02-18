use crate::config::{TAG_MAX_LEN, TAG_MIN_LEN};
use crate::model::AuditState;
use serde_json::Value;

pub(crate) fn apply_audit_filter(state: &mut AuditState) {
    if state.filter.trim().is_empty() {
        state.filtered_indices = (0..state.events.len()).collect();
    } else {
        let needle = state.filter.to_lowercase();
        let mut filtered = Vec::new();
        for (idx, event) in state.events.iter().enumerate() {
            let hay = event.to_string().to_lowercase();
            if hay.contains(&needle) {
                filtered.push(idx);
            }
        }
        state.filtered_indices = filtered;
    }
    if state.filtered_indices.is_empty() {
        state.selected = 0;
    } else if state.selected >= state.filtered_indices.len() {
        state.selected = state.filtered_indices.len() - 1;
    }
}

pub(crate) fn audit_event_label(root: &Value) -> String {
    let event_type = root
        .get("event")
        .and_then(|v| v.get("event_type"))
        .and_then(|v| v.as_str())
        .or_else(|| root.get("event_type").and_then(|v| v.as_str()))
        .or_else(|| root.get("type").and_then(|v| v.as_str()))
        .unwrap_or("unknown");
    let tag = audit_event_tag(root);
    if tag.is_empty() {
        event_type.to_string()
    } else {
        format!("{} {}", event_type, tag)
    }
}

pub(crate) fn audit_event_tag(root: &Value) -> String {
    let event = root.get("event");
    let tag_value = event
        .and_then(|v| v.get("run_id"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            event
                .and_then(|v| v.get("final_state_hash"))
                .and_then(|v| v.as_str())
        })
        .or_else(|| root.get("hash").and_then(|v| v.as_str()));
    match tag_value {
        Some(value) => tag_prefix(value),
        None => String::new(),
    }
}

pub(crate) fn tag_prefix(value: &str) -> String {
    let trimmed = value.strip_prefix("sha256:").unwrap_or(value);
    let len = trimmed.len();
    let take = if len >= TAG_MAX_LEN {
        TAG_MAX_LEN
    } else if len >= TAG_MIN_LEN {
        len
    } else {
        len
    };
    trimmed.chars().take(take).collect()
}
