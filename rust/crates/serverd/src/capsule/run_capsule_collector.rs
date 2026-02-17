use crate::capsule::run_capsule::{
    RunCapsule, RunCapsuleAudit, RunCapsuleContext, RunCapsuleProvider, RunCapsuleRouter,
    RunCapsuleRun, RunCapsuleSkill, RunCapsuleState, RunCapsuleToolIo, RunCapsuleTools,
    RUN_CAPSULE_SCHEMA,
};

struct RunCapsuleStateTracker {
    initial_state_hash: String,
    state_delta_refs: Vec<String>,
    final_state_hash: Option<String>,
}

pub(crate) struct RunCapsuleCollector {
    run: RunCapsuleRun,
    skill: Option<RunCapsuleSkill>,
    router: Option<RunCapsuleRouter>,
    tools: Option<RunCapsuleTools>,
    context: Option<RunCapsuleContext>,
    providers: Vec<RunCapsuleProvider>,
    tool_io: Vec<RunCapsuleToolIo>,
    state: Option<RunCapsuleStateTracker>,
}

impl RunCapsuleCollector {
    pub(crate) fn new(run: RunCapsuleRun, initial_state_hash: Option<String>) -> Self {
        let state = initial_state_hash.map(|hash| RunCapsuleStateTracker {
            initial_state_hash: hash,
            state_delta_refs: Vec::new(),
            final_state_hash: None,
        });
        Self {
            run,
            skill: None,
            router: None,
            tools: None,
            context: None,
            providers: Vec::new(),
            tool_io: Vec::new(),
            state,
        }
    }

    pub(crate) fn set_skill(&mut self, skill: RunCapsuleSkill) {
        self.skill = Some(skill);
    }

    pub(crate) fn set_router_hash(&mut self, router_config_hash: String) {
        self.router = Some(RunCapsuleRouter { router_config_hash });
    }

    pub(crate) fn set_tool_registry_hash(&mut self, tool_registry_hash: String) {
        let tools = self.tools.get_or_insert(RunCapsuleTools {
            tool_registry_hash: None,
            tool_policy_hash: None,
        });
        tools.tool_registry_hash = Some(tool_registry_hash);
    }

    pub(crate) fn set_tool_policy_hash(&mut self, tool_policy_hash: String) {
        let tools = self.tools.get_or_insert(RunCapsuleTools {
            tool_registry_hash: None,
            tool_policy_hash: None,
        });
        tools.tool_policy_hash = Some(tool_policy_hash);
    }

    pub(crate) fn tool_registry_hash_is_none(&self) -> bool {
        self.tools
            .as_ref()
            .and_then(|tools| tools.tool_registry_hash.as_ref())
            .is_none()
    }

    pub(crate) fn tool_policy_hash_is_none(&self) -> bool {
        self.tools
            .as_ref()
            .and_then(|tools| tools.tool_policy_hash.as_ref())
            .is_none()
    }

    fn context_mut(&mut self) -> &mut RunCapsuleContext {
        if self.context.is_none() {
            self.context = Some(RunCapsuleContext {
                context_refs: Vec::new(),
                prompt_refs: Vec::new(),
                policy_ref: None,
                prompt_template_refs: Vec::new(),
            });
        }
        self.context.as_mut().expect("context just set")
    }

    pub(crate) fn set_context_policy_ref(&mut self, policy_ref: String) {
        let context = self.context_mut();
        context.policy_ref = Some(policy_ref);
    }

    pub(crate) fn add_context_ref(&mut self, context_ref: String) {
        self.context_mut().context_refs.push(context_ref);
    }

    pub(crate) fn add_prompt_ref(&mut self, prompt_ref: String) {
        self.context_mut().prompt_refs.push(prompt_ref);
    }

    pub(crate) fn set_prompt_template_refs(&mut self, prompt_template_refs: Vec<String>) {
        self.context_mut().prompt_template_refs = prompt_template_refs;
    }

    pub(crate) fn ensure_state(&mut self, initial_state_hash: String) {
        if self.state.is_none() {
            self.state = Some(RunCapsuleStateTracker {
                initial_state_hash,
                state_delta_refs: Vec::new(),
                final_state_hash: None,
            });
        }
    }

    pub(crate) fn add_provider(&mut self, provider: RunCapsuleProvider) {
        self.providers.push(provider);
    }

    pub(crate) fn add_tool_io(&mut self, tool_io: RunCapsuleToolIo) {
        self.tool_io.push(tool_io);
    }

    pub(crate) fn add_state_delta_ref(&mut self, delta_ref: String, next_state_hash: String) {
        if let Some(state) = self.state.as_mut() {
            state.state_delta_refs.push(delta_ref);
            state.final_state_hash = Some(next_state_hash);
        }
    }

    pub(crate) fn finalize(
        mut self,
        audit_head_hash: String,
        final_state_hash: Option<String>,
    ) -> RunCapsule {
        let state = if let Some(mut state) = self.state.take() {
            if state.final_state_hash.is_none() {
                state.final_state_hash =
                    final_state_hash.or_else(|| Some(state.initial_state_hash.clone()));
            }
            Some(RunCapsuleState {
                initial_state_hash: state.initial_state_hash,
                final_state_hash: state
                    .final_state_hash
                    .unwrap_or_else(|| "sha256:".to_string()),
                state_delta_refs: state.state_delta_refs,
            })
        } else {
            None
        };
        let context = self.context.and_then(|ctx| {
            if ctx.context_refs.is_empty()
                && ctx.prompt_refs.is_empty()
                && ctx.policy_ref.is_none()
                && ctx.prompt_template_refs.is_empty()
            {
                None
            } else {
                Some(ctx)
            }
        });
        RunCapsule {
            schema: RUN_CAPSULE_SCHEMA.to_string(),
            run: self.run,
            skill: self.skill,
            router: self.router,
            tools: self.tools,
            context,
            providers: if self.providers.is_empty() {
                None
            } else {
                Some(self.providers)
            },
            tool_io: if self.tool_io.is_empty() {
                None
            } else {
                Some(self.tool_io)
            },
            state,
            audit: RunCapsuleAudit { audit_head_hash },
        }
    }
}
