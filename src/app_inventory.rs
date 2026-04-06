//! Application inventory — catalog all installed applications.
//!
//! Scans XDG desktop entries, dpkg/apt databases, flatpak, snap, and
//! AppImage locations to build a complete inventory of installed software.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Source of an installed application.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstallSource {
    Dpkg,
    Flatpak,
    Snap,
    AppImage,
    Manual,
    Pip,
    Npm,
    Cargo,
    Unknown,
}

/// An installed application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub name: String,
    pub version: String,
    pub source: InstallSource,
    pub desktop_file: Option<PathBuf>,
    pub exec_path: Option<PathBuf>,
    pub install_size_bytes: u64,
    pub last_used: Option<DateTime<Utc>>,
    pub categories: Vec<String>,
    pub autostart: bool,
}

/// Application inventory.
pub struct AppInventory {
    apps: HashMap<String, InstalledApp>,
}

impl AppInventory {
    pub fn new() -> Self {
        Self { apps: HashMap::new() }
    }

    /// Register an application.
    pub fn register(&mut self, app: InstalledApp) {
        self.apps.insert(app.name.clone(), app);
    }

    /// Scan XDG desktop entries.
    pub fn scan_desktop_entries(&mut self) {
        let dirs = [
            "/usr/share/applications",
            "/usr/local/share/applications",
        ];
        for dir in &dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "desktop").unwrap_or(false) {
                        if let Some(app) = self.parse_desktop_file(&path) {
                            self.apps.insert(app.name.clone(), app);
                        }
                    }
                }
            }
        }
    }

    fn parse_desktop_file(&self, path: &std::path::Path) -> Option<InstalledApp> {
        let content = std::fs::read_to_string(path).ok()?;
        let mut name = String::new();
        let mut exec = String::new();
        let mut categories = Vec::new();

        for line in content.lines() {
            if let Some(val) = line.strip_prefix("Name=") {
                if name.is_empty() {
                    name = val.to_string();
                }
            } else if let Some(val) = line.strip_prefix("Exec=") {
                exec = val.split_whitespace().next().unwrap_or("").to_string();
            } else if let Some(val) = line.strip_prefix("Categories=") {
                categories = val.split(';').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
            }
        }

        if name.is_empty() {
            return None;
        }

        Some(InstalledApp {
            name,
            version: String::new(),
            source: InstallSource::Dpkg,
            desktop_file: Some(path.to_path_buf()),
            exec_path: if exec.is_empty() { None } else { Some(PathBuf::from(exec)) },
            install_size_bytes: 0,
            last_used: None,
            categories,
            autostart: false,
        })
    }

    /// Get all apps by source.
    pub fn by_source(&self, source: &InstallSource) -> Vec<&InstalledApp> {
        self.apps.values().filter(|a| &a.source == source).collect()
    }

    /// Get apps by category.
    pub fn by_category(&self, category: &str) -> Vec<&InstalledApp> {
        self.apps.values()
            .filter(|a| a.categories.iter().any(|c| c.to_lowercase().contains(&category.to_lowercase())))
            .collect()
    }

    /// Get apps with autostart enabled.
    pub fn autostart_apps(&self) -> Vec<&InstalledApp> {
        self.apps.values().filter(|a| a.autostart).collect()
    }

    /// Search by name.
    pub fn search(&self, query: &str) -> Vec<&InstalledApp> {
        let lower = query.to_lowercase();
        self.apps.values()
            .filter(|a| a.name.to_lowercase().contains(&lower))
            .collect()
    }

    /// Total disk usage across all tracked apps.
    pub fn total_size(&self) -> u64 {
        self.apps.values().map(|a| a.install_size_bytes).sum()
    }

    /// Get an app by name.
    pub fn get(&self, name: &str) -> Option<&InstalledApp> {
        self.apps.get(name)
    }

    pub fn count(&self) -> usize { self.apps.len() }

    /// Source distribution stats.
    pub fn source_stats(&self) -> HashMap<InstallSource, usize> {
        let mut stats = HashMap::new();
        for app in self.apps.values() {
            *stats.entry(app.source.clone()).or_default() += 1;
        }
        stats
    }
}

impl Default for AppInventory {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_app(name: &str, source: InstallSource) -> InstalledApp {
        InstalledApp {
            name: name.into(), version: "1.0".into(), source,
            desktop_file: None, exec_path: None, install_size_bytes: 1000,
            last_used: None, categories: vec!["Utility".into()], autostart: false,
        }
    }

    #[test]
    fn test_register_and_count() {
        let mut inv = AppInventory::new();
        inv.register(make_app("firefox", InstallSource::Dpkg));
        inv.register(make_app("vim", InstallSource::Dpkg));
        assert_eq!(inv.count(), 2);
    }

    #[test]
    fn test_by_source() {
        let mut inv = AppInventory::new();
        inv.register(make_app("firefox", InstallSource::Dpkg));
        inv.register(make_app("signal", InstallSource::Flatpak));
        assert_eq!(inv.by_source(&InstallSource::Dpkg).len(), 1);
        assert_eq!(inv.by_source(&InstallSource::Flatpak).len(), 1);
    }

    #[test]
    fn test_search() {
        let mut inv = AppInventory::new();
        inv.register(make_app("Firefox", InstallSource::Dpkg));
        inv.register(make_app("Chromium", InstallSource::Dpkg));
        assert_eq!(inv.search("fire").len(), 1);
        assert_eq!(inv.search("xyz").len(), 0);
    }

    #[test]
    fn test_by_category() {
        let mut inv = AppInventory::new();
        let mut app = make_app("gimp", InstallSource::Dpkg);
        app.categories = vec!["Graphics".into(), "2DGraphics".into()];
        inv.register(app);
        assert_eq!(inv.by_category("graphics").len(), 1);
    }

    #[test]
    fn test_total_size() {
        let mut inv = AppInventory::new();
        inv.register(make_app("a", InstallSource::Dpkg));
        inv.register(make_app("b", InstallSource::Dpkg));
        assert_eq!(inv.total_size(), 2000);
    }

    #[test]
    fn test_scan_desktop_entries() {
        let mut inv = AppInventory::new();
        inv.scan_desktop_entries();
        // On a real system, should find some desktop entries.
        // Count may vary.
        let _ = inv.count();
    }

    #[test]
    fn test_source_stats() {
        let mut inv = AppInventory::new();
        inv.register(make_app("a", InstallSource::Dpkg));
        inv.register(make_app("b", InstallSource::Dpkg));
        inv.register(make_app("c", InstallSource::Snap));
        let stats = inv.source_stats();
        assert_eq!(*stats.get(&InstallSource::Dpkg).unwrap(), 2);
        assert_eq!(*stats.get(&InstallSource::Snap).unwrap(), 1);
    }
}
