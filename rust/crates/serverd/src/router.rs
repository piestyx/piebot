use crate::provider::ProviderId;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const ROUTER_SCHEMA: &str = "serverd.router.v1";

#[derive(Debug)]
pub struct RouterError {
    reason: &'static str,
    source: Option<std::io::Error>,
}

impl RouterError {
    pub fn new(reason: &'static str) -> Self {
        Self {
            reason,
            source: None,
        }
    }

    pub fn with_source(reason: &'static str, source: std::io::Error) -> Self {
        Self {
            reason,
            source: Some(source),
        }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for RouterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RouterConfig {
    pub schema: String,
    pub default_provider: String,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
    #[serde(default)]
    pub policy: RouterPolicy,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            schema: ROUTER_SCHEMA.to_string(),
            default_provider: "mock".to_string(),
            routes: Vec::new(),
            policy: RouterPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RouterPolicy {
    pub fail_if_unavailable: bool,
}

impl Default for RouterPolicy {
    fn default() -> Self {
        Self {
            fail_if_unavailable: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RouteRule {
    pub when: RouteWhen,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RouteWhen {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub task_kind: Option<String>,
    #[serde(default)]
    pub tick_mod: Option<u64>,
    #[serde(default)]
    pub state_hash_prefix: Option<String>,
}

pub struct RouteInput<'a> {
    pub mode: &'a str,
    pub tick_index: u64,
    pub task_kind: Option<&'a str>,
    pub state_hash: Option<&'a str>,
}

pub struct RouteDecision {
    pub provider_id: ProviderId,
    pub reason: String,
}

fn router_config_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("router").join("config.json")
}

pub fn load_router_config(runtime_root: &Path) -> Result<RouterConfig, RouterError> {
    let path = router_config_path(runtime_root);
    if !path.exists() {
        return Ok(RouterConfig::default());
    }
    let bytes =
        fs::read(&path).map_err(|e| RouterError::with_source("router_config_read_failed", e))?;
    let config: RouterConfig =
        serde_json::from_slice(&bytes).map_err(|_| RouterError::new("router_config_invalid"))?;
    if config.schema != ROUTER_SCHEMA {
        return Err(RouterError::new("router_config_invalid"));
    }
    validate_config(&config)?;
    Ok(config)
}

fn validate_config(config: &RouterConfig) -> Result<(), RouterError> {
    if ProviderId::parse(&config.default_provider).is_err() {
        return Err(RouterError::new("router_config_invalid"));
    }
    for rule in &config.routes {
        if ProviderId::parse(&rule.provider).is_err() {
            return Err(RouterError::new("router_config_invalid"));
        }
        if let Some(modulus) = rule.when.tick_mod {
            if modulus == 0 {
                return Err(RouterError::new("router_config_invalid"));
            }
        }
    }
    Ok(())
}

pub fn select_provider(
    config: &RouterConfig,
    input: &RouteInput<'_>,
) -> Result<RouteDecision, RouterError> {
    for (idx, rule) in config.routes.iter().enumerate() {
        if matches_rule(rule, input) {
            let provider_id = ProviderId::parse(&rule.provider)
                .map_err(|_| RouterError::new("router_config_invalid"))?;
            return Ok(RouteDecision {
                provider_id,
                reason: format!("route:{}", idx),
            });
        }
    }
    let provider_id = ProviderId::parse(&config.default_provider)
        .map_err(|_| RouterError::new("router_config_invalid"))?;
    Ok(RouteDecision {
        provider_id,
        reason: "default".to_string(),
    })
}

fn matches_rule(rule: &RouteRule, input: &RouteInput<'_>) -> bool {
    if let Some(mode) = &rule.when.mode {
        if mode != input.mode {
            return false;
        }
    }
    if let Some(task_kind) = &rule.when.task_kind {
        if input
            .task_kind
            .map(|k| k != task_kind.as_str())
            .unwrap_or(true)
        {
            return false;
        }
    }
    if let Some(modulus) = rule.when.tick_mod {
        if modulus == 0 || !input.tick_index.is_multiple_of(modulus) {
            return false;
        }
    }
    if let Some(prefix) = &rule.when.state_hash_prefix {
        if input
            .state_hash
            .map(|h| !h.starts_with(prefix))
            .unwrap_or(true)
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn router_config_defaults_when_missing() {
        let root = std::env::temp_dir().join(format!("pie_router_default_{}", Uuid::new_v4()));
        let config = load_router_config(&root).expect("load config");
        assert_eq!(config, RouterConfig::default());
    }

    #[test]
    fn router_config_invalid_schema_fails() {
        let root =
            std::env::temp_dir().join(format!("pie_router_invalid_schema_{}", Uuid::new_v4()));
        let dir = root.join("router");
        fs::create_dir_all(&dir).expect("create dir");
        let value = serde_json::json!({
            "schema": "wrong.schema",
            "default_provider": "mock",
            "routes": [],
            "policy": { "fail_if_unavailable": true }
        });
        let bytes = serde_json::to_vec(&value).expect("serialize");
        fs::write(dir.join("config.json"), bytes).expect("write config");
        let err = load_router_config(&root).expect_err("should fail");
        assert_eq!(err.reason(), "router_config_invalid");
    }

    #[test]
    fn router_selection_is_deterministic() {
        let config = RouterConfig {
            schema: ROUTER_SCHEMA.to_string(),
            default_provider: "mock".to_string(),
            routes: vec![RouteRule {
                when: RouteWhen {
                    mode: Some("route".to_string()),
                    task_kind: None,
                    tick_mod: Some(2),
                    state_hash_prefix: None,
                },
                provider: "null".to_string(),
            }],
            policy: RouterPolicy::default(),
        };
        let input = RouteInput {
            mode: "route",
            tick_index: 2,
            task_kind: Some("no_op"),
            state_hash: Some("sha256:abc"),
        };
        let first = select_provider(&config, &input).expect("select one");
        let second = select_provider(&config, &input).expect("select two");
        assert_eq!(first.provider_id.as_str(), second.provider_id.as_str());
        assert_eq!(first.reason, second.reason);
    }
}
