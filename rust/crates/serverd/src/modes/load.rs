pub fn load_mode_config(runtime_root: &Path) -> Result<ModeConfig, ModeError> {
    let path = mode_config_path(runtime_root);
    if !path.exists() {
        return Ok(ModeConfig::default());
    }
    let bytes = fs::read(&path)
        .map_err(|e| ModeError::with_detail("mode_config_invalid", e.to_string()))?;
    let mut config: ModeConfig = serde_json::from_slice(&bytes)
        .map_err(|e| ModeError::with_detail("mode_config_invalid", e.to_string()))?;
    if config.schema != MODE_CONFIG_SCHEMA {
        return Err(ModeError::new("mode_config_invalid"));
    }
    normalize_mode_config(&mut config)?;
    Ok(config)
}

pub fn load_mode_route_config(
    runtime_root: &Path,
    mode_config: &ModeConfig,
) -> Result<LoadedModeRouteConfig, ModeError> {
    let path = mode_route_path(runtime_root);
    if !path.exists() {
        return Ok(LoadedModeRouteConfig {
            config: ModeRouteConfig::default(),
            loaded_from_file: false,
        });
    }
    let bytes =
        fs::read(&path).map_err(|e| ModeError::with_detail("mode_route_invalid", e.to_string()))?;
    let mut config: ModeRouteConfig = serde_json::from_slice(&bytes)
        .map_err(|e| ModeError::with_detail("mode_route_invalid", e.to_string()))?;
    if config.schema != MODE_ROUTE_SCHEMA {
        return Err(ModeError::new("mode_route_invalid"));
    }
    normalize_mode_route_config(&mut config)?;
    if mode_config.enabled {
        for mode_id in config.by_skill.values() {
            if !mode_config
                .allowed_modes
                .iter()
                .any(|value| value == mode_id)
            {
                return Err(ModeError::new("mode_not_allowed"));
            }
        }
    }
    Ok(LoadedModeRouteConfig {
        config,
        loaded_from_file: true,
    })
}

pub fn resolve_selected_mode(
    config: &ModeConfig,
    selected_mode_override: Option<&str>,
) -> Result<Option<String>, ModeError> {
    if !config.enabled {
        return Ok(None);
    }
    let selected = selected_mode_override.unwrap_or(config.default_mode.as_str());
    if !config.allowed_modes.iter().any(|value| value == selected) {
        return Err(ModeError::new("mode_not_allowed"));
    }
    Ok(Some(selected.to_string()))
}

pub fn resolve_selected_mode_with_route(
    mode_config: &ModeConfig,
    route_cfg: &ModeRouteConfig,
    selected_mode_override: Option<&str>,
    skill_id: Option<&str>,
) -> Result<Option<String>, ModeError> {
    if !mode_config.enabled {
        return Ok(None);
    }
    if let Some(selected_mode) = selected_mode_override {
        return resolve_selected_mode(mode_config, Some(selected_mode));
    }
    if let Some(skill_id) = skill_id {
        if let Some(mode_id) = route_cfg.by_skill.get(skill_id) {
            if !mode_config
                .allowed_modes
                .iter()
                .any(|value| value == mode_id)
            {
                return Err(ModeError::new("mode_not_allowed"));
            }
            return Ok(Some(mode_id.clone()));
        }
    }
    resolve_selected_mode(mode_config, None)
}

pub fn load_mode_profile(
    runtime_root: &Path,
    mode_id: &str,
    max_profile_bytes: u64,
) -> Result<ModeProfile, ModeError> {
    if !is_safe_token(mode_id) {
        return Err(ModeError::new("mode_not_allowed"));
    }
    let path = mode_profile_path(runtime_root, mode_id);
    if !path.is_file() {
        return Err(ModeError::new("mode_profile_missing"));
    }
    let metadata = fs::metadata(&path)
        .map_err(|e| ModeError::with_detail("mode_profile_invalid", e.to_string()))?;
    if metadata.len() > max_profile_bytes {
        return Err(ModeError::new("mode_profile_too_large"));
    }
    let bytes = fs::read(&path)
        .map_err(|e| ModeError::with_detail("mode_profile_invalid", e.to_string()))?;
    let mut profile: ModeProfile = serde_json::from_slice(&bytes)
        .map_err(|e| ModeError::with_detail("mode_profile_invalid", e.to_string()))?;
    if profile.schema != MODE_PROFILE_SCHEMA {
        return Err(ModeError::new("mode_profile_invalid"));
    }
    normalize_mode_profile(&mut profile)?;
    if profile.mode_id != mode_id {
        return Err(ModeError::new("mode_profile_invalid"));
    }
    Ok(profile)
}

