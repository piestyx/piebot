pub(crate) fn is_safe_token(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

pub(crate) fn split_explicit_ref(value: &str) -> Option<(&str, &str)> {
    let (namespace, rest) = value.split_once('/')?;
    if namespace.is_empty() || rest.is_empty() || rest.contains('/') {
        return None;
    }
    if !is_safe_token(namespace) {
        return None;
    }
    Some((namespace, rest))
}

pub(crate) fn split_ref_parts_with_default(
    value: &str,
    default_namespace: &str,
) -> Option<(String, String)> {
    match value.split_once('/') {
        Some(_) => split_explicit_ref(value).map(|(ns, id)| (ns.to_string(), id.to_string())),
        None => {
            if !is_safe_token(default_namespace) || value.is_empty() || value.contains('/') {
                return None;
            }
            Some((default_namespace.to_string(), value.to_string()))
        }
    }
}

pub(crate) fn normalize_ref(namespace: &str, id: &str) -> Option<String> {
    if !is_safe_token(namespace) || id.is_empty() || id.contains('/') {
        return None;
    }
    Some(format!("{}/{}", namespace, id))
}
