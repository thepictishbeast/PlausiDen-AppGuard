//! App archival — preserves user data while removing the binary.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveAction {
    pub app_id: String,
    pub binary_path: PathBuf,
    pub data_paths: Vec<PathBuf>,
    pub space_freed_bytes: u64,
    pub archived_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub app_id: String,
    pub original_binary: PathBuf,
    pub data_paths: Vec<PathBuf>,
    pub archived_at: DateTime<Utc>,
    pub binary_size: u64,
}

/// Archive an app — remove binary, keep data, save manifest for restore.
pub fn archive_app(app_id: &str, binary_path: &Path, data_paths: Vec<PathBuf>) -> Result<ArchiveAction, String> {
    if !binary_path.exists() {
        return Err(format!("binary not found: {}", binary_path.display()));
    }

    let binary_size = std::fs::metadata(binary_path)
        .map(|m| m.len())
        .map_err(|e| e.to_string())?;

    // Save manifest before removing
    let manifest = ArchiveManifest {
        app_id: app_id.to_string(),
        original_binary: binary_path.to_path_buf(),
        data_paths: data_paths.clone(),
        archived_at: Utc::now(),
        binary_size,
    };

    let manifest_path = binary_path.with_extension("archive-manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    std::fs::write(&manifest_path, manifest_json).map_err(|e| e.to_string())?;

    // Remove the binary
    std::fs::remove_file(binary_path).map_err(|e| e.to_string())?;

    Ok(ArchiveAction {
        app_id: app_id.to_string(),
        binary_path: binary_path.to_path_buf(),
        data_paths,
        space_freed_bytes: binary_size,
        archived_at: Utc::now(),
    })
}

/// Restore — reads manifest, but actual binary re-download is platform-specific.
pub fn restore_app(manifest_path: &Path) -> Result<ArchiveManifest, String> {
    let content = std::fs::read_to_string(manifest_path).map_err(|e| e.to_string())?;
    let manifest: ArchiveManifest = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_archive_and_restore() {
        let dir = TempDir::new().unwrap();
        let binary = dir.path().join("app.bin");
        std::fs::write(&binary, vec![0u8; 1024]).unwrap();

        let result = archive_app("com.test", &binary, vec![dir.path().join("data")]).unwrap();
        assert_eq!(result.space_freed_bytes, 1024);
        assert!(!binary.exists(), "binary should be removed");

        let manifest_path = dir.path().join("app.archive-manifest.json");
        assert!(manifest_path.exists(), "manifest should exist");

        let manifest = restore_app(&manifest_path).unwrap();
        assert_eq!(manifest.app_id, "com.test");
        assert_eq!(manifest.binary_size, 1024);
    }

    #[test]
    fn test_archive_missing_binary() {
        let result = archive_app("com.missing", Path::new("/nonexistent/app"), vec![]);
        assert!(result.is_err());
    }
}
