use std::env;

pub(crate) const MAX_PREVIEW_BYTES: usize = 16 * 1024;
pub(crate) const MAX_JSON_BYTES: usize = 256 * 1024;
pub(crate) const MAX_LOG_BYTES: usize = 32 * 1024;
pub(crate) const TICK_MILLIS: u64 = 400;
pub(crate) const TAG_MAX_LEN: usize = 12;
pub(crate) const TAG_MIN_LEN: usize = 8;
pub(crate) const MAX_PROCESS_OUTPUT_BYTES: usize = 256 * 1024;
pub(crate) const MAX_PROCESS_LINES: usize = 2000;

pub(crate) fn supports_truecolor() -> bool {
    env::var("COLORTERM")
        .ok()
        .map(|v| {
            let lower = v.to_lowercase();
            lower.contains("truecolor") || lower.contains("24bit")
        })
        .unwrap_or(false)
}

pub(crate) fn read_flag_envs() -> Vec<(String, String)> {
    let vars = [
        "TOOLS_ENABLE",
        "TOOLS_ARM",
        "OPEN_MEMORY_ENABLE",
        "PIE_RUNTIME_ROOT",
        "PIEBOT_SERVERD_BIN",
    ];
    vars.iter()
        .map(|key| {
            let value = env::var(key).unwrap_or_else(|_| "unset".to_string());
            (key.to_string(), value)
        })
        .collect()
}
