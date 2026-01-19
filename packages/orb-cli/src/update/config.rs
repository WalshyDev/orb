use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

const DEFAULT_MANIFEST_URL: &str = "https://orb-tools.com/update/manifest.json";
const DEFAULT_CHECK_INTERVAL_HOURS: u64 = 24;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub update: UpdateConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_check_interval")]
    pub check_interval_hours: u64,

    #[serde(default = "default_manifest_url")]
    pub manifest_url: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_hours: DEFAULT_CHECK_INTERVAL_HOURS,
            manifest_url: DEFAULT_MANIFEST_URL.to_string(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_check_interval() -> u64 {
    DEFAULT_CHECK_INTERVAL_HOURS
}

fn default_manifest_url() -> String {
    DEFAULT_MANIFEST_URL.to_string()
}

impl UpdateConfig {
    pub fn check_interval(&self) -> Duration {
        Duration::from_secs(self.check_interval_hours * 60 * 60)
    }
}

impl Config {
    /// Load config from ~/.config/orb/config.toml
    /// Returns default config if file doesn't exist or can't be parsed
    pub fn load() -> Self {
        let config_path = match config_file_path() {
            Some(p) => p,
            None => return Config::default(),
        };

        let content = match fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(_) => return Config::default(),
        };

        toml::from_str(&content).unwrap_or_default()
    }
}

/// Get the config directory path (~/.config/orb)
/// Can be overridden with ORB_CONFIG_DIR environment variable (useful for testing)
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("ORB_CONFIG_DIR") {
        return Some(PathBuf::from(dir));
    }
    dirs::config_dir().map(|p| p.join("orb"))
}

/// Get the config file path (~/.config/orb/config.toml)
pub fn config_file_path() -> Option<PathBuf> {
    config_dir().map(|p| p.join("config.toml"))
}

/// Get the state file path (~/.config/orb/state.json)
pub fn state_file_path() -> Option<PathBuf> {
    config_dir().map(|p| p.join("state.json"))
}

/// Get the staged updates directory (~/.config/orb/staged)
pub fn staged_dir() -> Option<PathBuf> {
    config_dir().map(|p| p.join("staged"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();

        assert!(config.update.enabled);
        assert_eq!(config.update.check_interval_hours, 24);
        assert_eq!(
            config.update.manifest_url,
            "https://orb-tools.com/update/manifest.json"
        );
    }

    #[test]
    fn test_check_interval() {
        let config = UpdateConfig {
            enabled: true,
            check_interval_hours: 12,
            manifest_url: "https://example.com".to_string(),
        };

        assert_eq!(config.check_interval(), Duration::from_secs(12 * 60 * 60));
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[update]
enabled = false
check_interval_hours = 168
manifest_url = "https://internal.example.com/manifest.json"
"#;

        let config: Config = toml::from_str(toml).unwrap();

        assert!(!config.update.enabled);
        assert_eq!(config.update.check_interval_hours, 168);
        assert_eq!(
            config.update.manifest_url,
            "https://internal.example.com/manifest.json"
        );
    }

    #[test]
    fn test_parse_partial_config() {
        let toml = r#"
[update]
enabled = false
"#;

        let config: Config = toml::from_str(toml).unwrap();

        assert!(!config.update.enabled);
        // Defaults should be applied
        assert_eq!(config.update.check_interval_hours, 24);
        assert_eq!(
            config.update.manifest_url,
            "https://orb-tools.com/update/manifest.json"
        );
    }

    #[test]
    fn test_parse_empty_config() {
        let toml = "";

        let config: Config = toml::from_str(toml).unwrap();

        // All defaults
        assert!(config.update.enabled);
        assert_eq!(config.update.check_interval_hours, 24);
    }

    #[test]
    fn test_config_dir_is_some() {
        // Should return Some on most systems
        let dir = config_dir();
        if let Some(path) = dir {
            assert!(path.to_string_lossy().contains("orb"));
        }
    }

    #[test]
    fn test_staged_dir_is_some() {
        let dir = staged_dir();
        if let Some(path) = dir {
            assert!(path.to_string_lossy().contains("staged"));
        }
    }
}
