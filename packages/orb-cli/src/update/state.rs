use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::config::state_file_path;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UpdateState {
    /// Last time we checked for updates
    pub last_check: Option<DateTime<Utc>>,

    /// Information about a staged update ready to be applied
    pub staged: Option<StagedUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedUpdate {
    /// Version of the staged update
    pub version: String,

    /// Path to the staged binary
    pub path: PathBuf,

    /// SHA256 hash of the staged binary
    pub sha256: String,
}

impl UpdateState {
    /// Load state from ~/.config/orb/state.json
    /// Returns default state if file doesn't exist or can't be parsed
    pub fn load() -> Self {
        let state_path = match state_file_path() {
            Some(p) => p,
            None => return UpdateState::default(),
        };

        let content = match fs::read_to_string(&state_path) {
            Ok(c) => c,
            Err(_) => return UpdateState::default(),
        };

        serde_json::from_str(&content).unwrap_or_default()
    }

    /// Save state to ~/.config/orb/state.json
    pub fn save(&self) -> Result<(), std::io::Error> {
        let state_path = match state_file_path() {
            Some(p) => p,
            None => return Ok(()), // Can't determine path, silently skip
        };

        // Ensure directory exists
        if let Some(parent) = state_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(self)?;
        fs::write(&state_path, content)?;

        Ok(())
    }

    /// Check if we should perform an update check based on the interval
    pub fn should_check(&self, interval: Duration) -> bool {
        match self.last_check {
            Some(last) => {
                let elapsed = Utc::now().signed_duration_since(last);
                elapsed.to_std().map(|d| d >= interval).unwrap_or(true)
            }
            None => true, // Never checked, should check now
        }
    }

    /// Mark that we've checked for updates now
    pub fn mark_checked(&mut self) {
        self.last_check = Some(Utc::now());
    }

    /// Set the staged update
    pub fn set_staged(&mut self, staged: StagedUpdate) {
        self.staged = Some(staged);
    }

    /// Clear the staged update (after applying)
    pub fn clear_staged(&mut self) {
        self.staged = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    #[test]
    fn test_default_state() {
        let state = UpdateState::default();

        assert!(state.last_check.is_none());
        assert!(state.staged.is_none());
    }

    #[test]
    fn test_should_check_never_checked() {
        let state = UpdateState::default();

        // Should always check if never checked
        assert!(state.should_check(Duration::from_secs(3600)));
    }

    #[test]
    fn test_should_check_recently_checked() {
        let state = UpdateState {
            last_check: Some(Utc::now()),
            ..Default::default()
        };

        // Should not check if just checked (interval is 1 hour)
        assert!(!state.should_check(Duration::from_secs(3600)));
    }

    #[test]
    fn test_should_check_old_check() {
        // Last check was 2 hours ago
        let state = UpdateState {
            last_check: Some(Utc::now() - TimeDelta::hours(2)),
            ..Default::default()
        };

        // Should check if interval is 1 hour
        assert!(state.should_check(Duration::from_secs(3600)));
    }

    #[test]
    fn test_mark_checked() {
        let mut state = UpdateState::default();
        assert!(state.last_check.is_none());

        state.mark_checked();

        assert!(state.last_check.is_some());
        // Should be within the last second
        let elapsed = Utc::now()
            .signed_duration_since(state.last_check.unwrap())
            .num_seconds();
        assert!(elapsed < 2);
    }

    #[test]
    fn test_set_and_clear_staged() {
        let mut state = UpdateState::default();
        assert!(state.staged.is_none());

        let staged = StagedUpdate {
            version: "0.3.0".to_string(),
            path: PathBuf::from("/tmp/orb-0.3.0"),
            sha256: "abc123".to_string(),
        };

        state.set_staged(staged);
        assert!(state.staged.is_some());
        assert_eq!(state.staged.as_ref().unwrap().version, "0.3.0");

        state.clear_staged();
        assert!(state.staged.is_none());
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut state = UpdateState::default();
        state.mark_checked();
        state.set_staged(StagedUpdate {
            version: "0.3.0".to_string(),
            path: PathBuf::from("/tmp/orb-0.3.0"),
            sha256: "abc123".to_string(),
        });

        let json = serde_json::to_string(&state).unwrap();
        let parsed: UpdateState = serde_json::from_str(&json).unwrap();

        assert!(parsed.last_check.is_some());
        assert!(parsed.staged.is_some());
        assert_eq!(parsed.staged.as_ref().unwrap().version, "0.3.0");
    }

    #[test]
    fn test_deserialize_empty_json() {
        let json = "{}";
        let state: UpdateState = serde_json::from_str(json).unwrap();

        assert!(state.last_check.is_none());
        assert!(state.staged.is_none());
    }
}
