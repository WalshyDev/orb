use std::fs;
use std::path::Path;

use super::UpdateError;
use super::download::verify_sha256;
use super::state::UpdateState;

/// Apply a staged update by replacing the current binary
/// Returns the new version string on success
pub fn apply_staged_update(state: &mut UpdateState) -> Result<Option<String>, UpdateError> {
    let staged = match &state.staged {
        Some(s) => s.clone(),
        None => return Ok(None),
    };

    // Verify the staged binary still exists
    if !staged.path.exists() {
        state.clear_staged();
        let _ = state.save();
        return Ok(None);
    }

    // Verify SHA256 before applying
    if !verify_sha256(&staged.path, &staged.sha256)? {
        // Hash mismatch - delete the staged file and clear state
        let _ = fs::remove_file(&staged.path);
        state.clear_staged();
        let _ = state.save();
        return Err(UpdateError::HashMismatch);
    }

    // Get current executable path
    let current_exe = std::env::current_exe().map_err(|_| UpdateError::IoError)?;

    // Apply the update
    replace_binary(&staged.path, &current_exe)?;

    // Clear the staged update
    let version = staged.version.clone();
    state.clear_staged();
    let _ = state.save();

    // Clean up the staged file (it's been copied/moved)
    let _ = fs::remove_file(&staged.path);

    Ok(Some(version))
}

/// Replace the current binary with the new one
#[cfg(unix)]
fn replace_binary(staged: &Path, current: &Path) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt;

    // Skip actual replacement in tests (prevents replacing the test binary)
    if std::env::var("ORB_UPDATE_DRY_RUN").is_ok() {
        return Ok(());
    }

    // Set executable permissions on staged binary
    let mut perms = fs::metadata(staged)
        .map_err(|_| UpdateError::IoError)?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(staged, perms).map_err(|_| UpdateError::IoError)?;

    // On Unix, we can atomically rename over the running executable
    fs::rename(staged, current).map_err(|_| UpdateError::IoError)?;

    Ok(())
}

/// Replace the current binary with the new one (Windows)
#[cfg(windows)]
fn replace_binary(staged: &Path, current: &Path) -> Result<(), UpdateError> {
    // Skip actual replacement in tests (prevents replacing the test binary)
    if std::env::var("ORB_UPDATE_DRY_RUN").is_ok() {
        return Ok(());
    }

    // On Windows, we can't rename over a running executable
    // Instead: rename current to .old, copy new, delete .old on next run

    let old_path = current.with_extension("exe.old");

    // Remove any previous .old file
    let _ = fs::remove_file(&old_path);

    // Rename current executable to .old
    fs::rename(current, &old_path).map_err(|_| UpdateError::IoError)?;

    // Copy staged binary to current location
    fs::copy(staged, current).map_err(|_| UpdateError::IoError)?;

    Ok(())
}

/// Clean up old Windows executables (.exe.old files)
#[cfg(windows)]
pub fn cleanup_old_binary() {
    if let Ok(current_exe) = std::env::current_exe() {
        let old_path = current_exe.with_extension("exe.old");
        let _ = fs::remove_file(old_path);
    }
}

#[cfg(not(windows))]
pub fn cleanup_old_binary() {
    // No cleanup needed on Unix
}
