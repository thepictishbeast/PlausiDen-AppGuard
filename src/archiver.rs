//! App archival — preserves user data while removing the binary.
//!
//! Like Android's auto-archive feature: the app icon stays with a cloud
//! indicator, user data is preserved, but the APK/binary is removed to
//! free space. Re-installing restores everything.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Archive action for an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveAction {
    pub app_id: String,
    pub binary_path: PathBuf,
    pub data_paths: Vec<PathBuf>,
    pub space_freed_bytes: u64,
}

/// Archive an app's binary while preserving data.
pub fn archive_app(_app_id: &str, _binary_path: &std::path::Path) -> Result<ArchiveAction, String> {
    todo!("archive_app: remove binary, keep data, update launcher")
}

/// Restore an archived app.
pub fn restore_app(_app_id: &str) -> Result<(), String> {
    todo!("restore_app: re-download binary, reconnect data")
}
