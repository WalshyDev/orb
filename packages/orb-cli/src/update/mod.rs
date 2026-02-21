mod apply;
mod config;
mod download;
mod manifest;
mod state;

use semver::Version;

use self::apply::{apply_staged_update, cleanup_old_binary};
use self::config::Config;
use self::download::{download_binary, verify_sha256};
use self::manifest::UpdateManifest;
use self::state::{StagedUpdate, UpdateState};

/// Error types for update operations
#[derive(Debug)]
pub enum UpdateError {
    /// Update checking is disabled
    Disabled,
    /// No config directory available
    NoConfigDir,
    /// Failed to parse manifest URL
    InvalidManifestUrl,
    /// Network request failed
    NetworkError,
    /// Request timed out
    Timeout,
    /// HTTP error response
    HttpError,
    /// Failed to parse manifest JSON
    InvalidManifest,
    /// Binary hash doesn't match expected
    HashMismatch,
    /// Platform not supported
    UnsupportedPlatform,
    /// File I/O error
    IoError,
    /// Failed to parse version
    VersionParse,
}

/// Initialize the update system - spawns background update check
/// This function returns immediately and does not block.
/// Returns a handle that can be awaited to ensure the check completes.
pub fn init() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Silently handle any errors - update failures should never disrupt the CLI
        let _ = check_and_stage_update().await;
    })
}

/// Apply any pending staged update
/// Call this at startup before argument parsing
/// Returns the new version if an update was applied
pub fn apply_pending() -> Option<String> {
    // Clean up any old Windows binaries first
    cleanup_old_binary();

    let mut state = UpdateState::load();

    state.staged.as_ref()?;

    apply_staged_update(&mut state).unwrap_or_default()
}

/// Check for updates and stage if available
async fn check_and_stage_update() -> Result<(), UpdateError> {
    let config = Config::load();

    // Check if updates are enabled
    if !config.update.enabled {
        return Err(UpdateError::Disabled);
    }

    let mut state = UpdateState::load();

    // Check if we should perform an update check (based on interval)
    if !state.should_check(config.update.check_interval()) {
        return Ok(());
    }

    // Fetch the manifest
    let manifest = UpdateManifest::fetch(&config.update.manifest_url).await?;

    // Update last check time
    state.mark_checked();
    let _ = state.save();

    // Compare versions
    let current_version =
        Version::parse(env!("CARGO_PKG_VERSION")).map_err(|_| UpdateError::VersionParse)?;
    let latest_version =
        Version::parse(&manifest.version).map_err(|_| UpdateError::VersionParse)?;

    // No update needed if current version is >= latest
    if current_version >= latest_version {
        return Ok(());
    }

    // Get binary info for current platform
    let binary_info = manifest
        .get_binary_for_platform()
        .ok_or(UpdateError::UnsupportedPlatform)?;

    // Download the binary
    let staged_path = download_binary(binary_info, &manifest.version).await?;

    // Verify the download
    if !verify_sha256(&staged_path, &binary_info.sha256)? {
        // Clean up failed download
        let _ = std::fs::remove_file(&staged_path);
        return Err(UpdateError::HashMismatch);
    }

    // Stage the update
    state.set_staged(StagedUpdate {
        version: manifest.version.clone(),
        path: staged_path,
        sha256: binary_info.sha256.clone(),
    });
    let _ = state.save();

    // Print notification for urgent updates only
    if manifest.urgent {
        eprintln!(
            "* Security update {} is ready. It will be applied on next run.",
            manifest.version
        );
    }

    Ok(())
}
