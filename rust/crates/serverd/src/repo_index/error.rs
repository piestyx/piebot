#[derive(Debug)]
pub(crate) struct RepoIndexError {
    reason: &'static str,
    detail: Option<String>,
}

impl RepoIndexError {
    pub(crate) fn new(reason: &'static str) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    pub(crate) fn with_detail(reason: &'static str, detail: String) -> Self {
        Self {
            reason,
            detail: Some(detail),
        }
    }

    pub(crate) fn reason(&self) -> &'static str {
        self.reason
    }

    #[allow(dead_code)]
    pub(crate) fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl std::fmt::Display for RepoIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.detail.as_ref() {
            Some(detail) => write!(f, "{}: {}", self.reason, detail),
            None => write!(f, "{}", self.reason),
        }
    }
}

impl std::error::Error for RepoIndexError {}
