//! Guarded cleanup for temporary kernel-vulnerability audit workspaces.

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

/// Remove only the direct `scratch/` child owned by one persistent workspace.
///
/// The caller invokes this only after the child agent has exited and required
/// findings have been copied to persistent artifact directories.
pub(super) fn cleanup_scratch_directory(workspace: &Path, scratch_dir: &Path) -> Result<()> {
    ensure!(
        scratch_dir.file_name().and_then(|name| name.to_str()) == Some("scratch"),
        "refusing to clean a directory not named scratch: {}",
        scratch_dir.display()
    );
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("canonicalizing workspace {}", workspace.display()))?;
    let scratch_parent = scratch_dir
        .parent()
        .context("scratch path has no parent directory")?
        .canonicalize()
        .with_context(|| {
            format!(
                "canonicalizing scratch parent {}",
                scratch_dir.parent().unwrap_or(scratch_dir).display()
            )
        })?;
    ensure!(
        scratch_parent == workspace,
        "refusing to clean scratch outside its workspace: {}",
        scratch_dir.display()
    );

    let metadata = match fs::symlink_metadata(scratch_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("checking scratch directory {}", scratch_dir.display()));
        }
    };
    ensure!(
        metadata.file_type().is_dir(),
        "refusing to remove non-directory or symlink scratch path {}",
        scratch_dir.display()
    );
    fs::remove_dir_all(scratch_dir)
        .with_context(|| format!("removing scratch directory {}", scratch_dir.display()))
}
