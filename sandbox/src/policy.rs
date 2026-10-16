//! The worker's seccomp policy: a reviewed default that consumers adjust per syscall.
//!
//! Adjustments are code in the measured enclave binary, never runtime input, so the
//! untrusted host cannot widen the policy.

use std::fmt::Write;

/// The reviewed default policy, embedded in the measured binary.
const DEFAULT_POLICY: &str = include_str!("../worker.policy");

/// Entries that hold the sandbox's launch, IPC and process model together.
const LOCKED: [&str; 5] = ["execveat", "getsockname", "getpeername", "clone", "clone3"];

/// Ordered `syscall: rule` entries in Minijail's policy syntax.
#[derive(Clone, Debug)]
pub struct Policy {
    entries: Vec<(String, String)>,
    error: Option<PolicyError>,
}

/// An adjustment the policy rejects; reported by [`Policy::render`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The entry belongs to the sandbox model and cannot change.
    #[error("seccomp entry {0} is locked")]
    Locked(String),
    /// Not a syscall name.
    #[error("invalid syscall name {0:?}")]
    InvalidSyscall(String),
    /// Empty or multi-line rule.
    #[error("invalid seccomp rule for {0}")]
    InvalidRule(String),
    /// Denying a syscall the policy does not allow, usually a typo.
    #[error("seccomp entry {0} is not in the policy")]
    Unknown(String),
    /// A syscall listed twice.
    #[error("duplicate seccomp entry {0}")]
    Duplicate(String),
}

impl Policy {
    /// The reviewed policy every worker starts from.
    ///
    /// # Panics
    /// Never: the embedded default is checked by this crate's tests.
    #[must_use]
    pub fn default_worker() -> Self {
        Self::parse(DEFAULT_POLICY).expect("embedded default seccomp policy is valid")
    }

    /// Adds or replaces one syscall's rule, e.g. `allow("sched_getaffinity", "1")`.
    #[must_use]
    pub fn allow(mut self, syscall: &str, rule: &str) -> Self {
        if let Err(error) = check_change(syscall).and_then(|()| check_rule(syscall, rule)) {
            self.error.get_or_insert(error);
            return self;
        }
        match self.entries.iter_mut().find(|(name, _)| name == syscall) {
            Some(entry) => entry.1 = rule.to_owned(),
            None => self.entries.push((syscall.to_owned(), rule.to_owned())),
        }
        self
    }

    /// Removes one syscall, so calling it kills the worker.
    #[must_use]
    pub fn deny(mut self, syscall: &str) -> Self {
        if let Err(error) = check_change(syscall) {
            self.error.get_or_insert(error);
            return self;
        }
        let before = self.entries.len();
        self.entries.retain(|(name, _)| name != syscall);
        if self.entries.len() == before {
            self.error
                .get_or_insert(PolicyError::Unknown(syscall.to_owned()));
        }
        self
    }

    /// Renders the policy for Minijail.
    ///
    /// # Errors
    /// Returns the first rejected adjustment.
    pub fn render(&self) -> Result<String, PolicyError> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        let mut text = String::new();
        for (name, rule) in &self.entries {
            let _ = writeln!(text, "{name}: {rule}");
        }
        Ok(text)
    }

    fn parse(text: &str) -> Result<Self, PolicyError> {
        let mut entries: Vec<(String, String)> = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, rule) = line
                .split_once(':')
                .ok_or_else(|| PolicyError::InvalidRule(line.to_owned()))?;
            let (name, rule) = (name.trim(), rule.trim());
            check_name(name)?;
            check_rule(name, rule)?;
            if entries.iter().any(|(existing, _)| existing == name) {
                return Err(PolicyError::Duplicate(name.to_owned()));
            }
            entries.push((name.to_owned(), rule.to_owned()));
        }
        Ok(Self {
            entries,
            error: None,
        })
    }
}

fn check_change(syscall: &str) -> Result<(), PolicyError> {
    check_name(syscall)?;
    if LOCKED.contains(&syscall) {
        return Err(PolicyError::Locked(syscall.to_owned()));
    }
    Ok(())
}

fn check_name(syscall: &str) -> Result<(), PolicyError> {
    let valid = !syscall.is_empty()
        && syscall
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(PolicyError::InvalidSyscall(syscall.to_owned()))
    }
}

fn check_rule(syscall: &str, rule: &str) -> Result<(), PolicyError> {
    if rule.trim().is_empty() || rule.contains(['\n', '\r', '#']) {
        return Err(PolicyError::InvalidRule(syscall.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_POLICY, Policy, PolicyError};

    /// Today's rules, comments and blank lines dropped.
    fn default_rules() -> Vec<String> {
        DEFAULT_POLICY
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn the_rendered_default_matches_the_reviewed_policy_rule_for_rule() {
        let rendered = Policy::default_worker().render().unwrap();
        assert_eq!(rendered.lines().collect::<Vec<_>>(), default_rules());
    }

    #[test]
    fn allow_adds_or_replaces_and_deny_removes_single_entries() {
        let rendered = Policy::default_worker()
            .allow("sched_setaffinity", "1")
            .allow("getrandom", "1")
            .deny("pause")
            .render()
            .unwrap();
        let lines: Vec<_> = rendered.lines().collect();
        assert!(lines.contains(&"sched_setaffinity: 1"));
        assert!(lines.contains(&"getrandom: 1"));
        assert!(!lines.iter().any(|line| line.starts_with("pause:")));
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("getrandom:"))
                .count(),
            1
        );
        assert_eq!(lines.len(), default_rules().len());
    }

    #[test]
    fn locked_invalid_and_unknown_adjustments_fail_rendering() {
        for (policy, expected) in [
            (
                Policy::default_worker().allow("execveat", "1"),
                PolicyError::Locked("execveat".into()),
            ),
            (
                Policy::default_worker().deny("getsockname"),
                PolicyError::Locked("getsockname".into()),
            ),
            (
                Policy::default_worker().allow("clone3", "1"),
                PolicyError::Locked("clone3".into()),
            ),
            (
                Policy::default_worker().allow("Read", "1"),
                PolicyError::InvalidSyscall("Read".into()),
            ),
            (
                Policy::default_worker().allow("read", ""),
                PolicyError::InvalidRule("read".into()),
            ),
            (
                Policy::default_worker().allow("read", "1\nexecve: 1"),
                PolicyError::InvalidRule("read".into()),
            ),
            (
                Policy::default_worker().deny("sched_setafinity"),
                PolicyError::Unknown("sched_setafinity".into()),
            ),
        ] {
            assert_eq!(policy.render(), Err(expected));
        }
    }

    #[test]
    fn the_first_rejected_adjustment_is_kept() {
        let policy = Policy::default_worker()
            .allow("execveat", "1")
            .deny("missing");
        assert_eq!(policy.render(), Err(PolicyError::Locked("execveat".into())));
    }

    #[test]
    fn parsing_rejects_duplicates_and_malformed_lines() {
        assert_eq!(
            Policy::parse("read: 1\nread: 1\n").unwrap_err(),
            PolicyError::Duplicate("read".into())
        );
        assert!(Policy::parse("read 1\n").is_err());
    }
}
