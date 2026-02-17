use crate::skills::SkillContext;
use serde::{Deserialize, Serialize};

pub const CONTEXT_SELECTION_SCHEMA: &str = "serverd.context_selection.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ContextSelection {
    pub schema: String,
    pub context_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordering: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
}

pub fn select_context(skill_ctx: Option<&SkillContext>) -> ContextSelection {
    let context_refs = match skill_ctx {
        Some(ctx) => ctx.manifest.prompt_template_refs.clone(),
        None => Vec::new(),
    };
    ContextSelection {
        schema: CONTEXT_SELECTION_SCHEMA.to_string(),
        context_refs,
        ordering: None,
        total_items: None,
        total_bytes: None,
    }
}
