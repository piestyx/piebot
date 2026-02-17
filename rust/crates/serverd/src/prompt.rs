use serde::{Deserialize, Serialize};

pub const PROMPT_SCHEMA: &str = "serverd.prompt.v1";
pub const PROMPT_TEMPLATE_SCHEMA: &str = "serverd.prompt_template.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PromptTemplateArtifact {
    pub schema: String,
    pub template_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PromptContextSnippet {
    pub context_ref: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PromptArtifact {
    pub schema: String,
    pub request_hash: String,
    pub intent_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill_id: Option<String>,
    pub prompt_template_refs: Vec<String>,
    pub context_ref: String,
    pub context_refs: Vec<String>,
    pub template_texts: Vec<String>,
    pub context_snippets: Vec<PromptContextSnippet>,
    pub rendered: String,
}
