//! Install tracker — monitor application installations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// An installation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallEvent {
    pub app_id: String,
    pub app_name: String,
    pub version: String,
    pub installed_at: DateTime<Utc>,
    pub source: InstallSource,
    pub installer_path: Option<PathBuf>,
    pub required_admin: bool,
    pub file_count: u32,
    pub total_bytes: u64,
    pub signed: bool,
    pub signer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstallSource {
    OfficialRepo,
    AppStore,
    ThirdPartyRepo,
    DirectDownload,
    SideloadedApk,
    DevelopmentBuild,
    Unknown,
}

impl InstallSource {
    /// Risk score (0.0 = safe, 1.0 = dangerous).
    pub fn risk_score(&self) -> f64 {
        match self {
            InstallSource::OfficialRepo => 0.1,
            InstallSource::AppStore => 0.15,
            InstallSource::ThirdPartyRepo => 0.4,
            InstallSource::DirectDownload => 0.6,
            InstallSource::SideloadedApk => 0.75,
            InstallSource::DevelopmentBuild => 0.5,
            InstallSource::Unknown => 0.8,
        }
    }
}

/// An install flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallFlag {
    pub app_id: String,
    pub flag_type: FlagType,
    pub confidence: f64,
    pub detail: String,
    pub raised_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlagType {
    UnsignedInstaller,
    UntrustedSource,
    SilentInstall,
    BatchInstall,
    UnusualHour,
    SuspiciousSigner,
}

/// Install tracker.
pub struct InstallTracker {
    events: Vec<InstallEvent>,
    flags: Vec<InstallFlag>,
    trusted_signers: std::collections::HashSet<String>,
    history_limit: usize,
}

impl InstallTracker {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            flags: Vec::new(),
            trusted_signers: std::collections::HashSet::new(),
            history_limit: 5000,
        }
    }

    /// Trust a signer.
    pub fn trust_signer(&mut self, signer: &str) {
        self.trusted_signers.insert(signer.into());
    }

    /// Record an install and return any flags raised.
    pub fn record(&mut self, event: InstallEvent) -> Vec<InstallFlag> {
        let mut raised = Vec::new();
        let now = Utc::now();

        if !event.signed {
            raised.push(InstallFlag {
                app_id: event.app_id.clone(),
                flag_type: FlagType::UnsignedInstaller,
                confidence: 0.8,
                detail: format!("unsigned installer for {}", event.app_name),
                raised_at: now,
            });
        }

        if let Some(signer) = &event.signer {
            if !self.trusted_signers.is_empty() && !self.trusted_signers.contains(signer) {
                raised.push(InstallFlag {
                    app_id: event.app_id.clone(),
                    flag_type: FlagType::SuspiciousSigner,
                    confidence: 0.65,
                    detail: format!("unknown signer: {}", signer),
                    raised_at: now,
                });
            }
        }

        if event.source.risk_score() >= 0.5 {
            raised.push(InstallFlag {
                app_id: event.app_id.clone(),
                flag_type: FlagType::UntrustedSource,
                confidence: event.source.risk_score(),
                detail: format!("source {:?} is untrusted", event.source),
                raised_at: now,
            });
        }

        // Batch install: >3 installs in last 5 minutes.
        let five_min_ago = now - chrono::Duration::seconds(300);
        let recent = self.events.iter().filter(|e| e.installed_at > five_min_ago).count();
        if recent >= 3 {
            raised.push(InstallFlag {
                app_id: event.app_id.clone(),
                flag_type: FlagType::BatchInstall,
                confidence: 0.6,
                detail: format!("{}+ installs in 5 minutes", recent + 1),
                raised_at: now,
            });
        }

        self.events.push(event);
        if self.events.len() > self.history_limit {
            self.events.remove(0);
        }
        self.flags.extend(raised.clone());
        raised
    }

    /// Installs by source.
    pub fn by_source(&self, source: &InstallSource) -> Vec<&InstallEvent> {
        self.events.iter().filter(|e| &e.source == source).collect()
    }

    /// Total bytes installed across all apps.
    pub fn total_bytes(&self) -> u64 {
        self.events.iter().map(|e| e.total_bytes).sum()
    }

    /// Installs in the last N days.
    pub fn recent(&self, days: i64) -> Vec<&InstallEvent> {
        let cutoff = Utc::now() - chrono::Duration::days(days);
        self.events.iter().filter(|e| e.installed_at > cutoff).collect()
    }

    /// Apps requiring admin rights.
    pub fn admin_required(&self) -> Vec<&InstallEvent> {
        self.events.iter().filter(|e| e.required_admin).collect()
    }

    /// Flags by type.
    pub fn flags_by_type(&self, kind: &FlagType) -> Vec<&InstallFlag> {
        self.flags.iter().filter(|f| &f.flag_type == kind).collect()
    }

    /// Events.
    pub fn events(&self) -> &[InstallEvent] {
        &self.events
    }

    /// Flags.
    pub fn flags(&self) -> &[InstallFlag] {
        &self.flags
    }

    pub fn event_count(&self) -> usize { self.events.len() }
    pub fn flag_count(&self) -> usize { self.flags.len() }
}

impl Default for InstallTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(app: &str, source: InstallSource, signed: bool) -> InstallEvent {
        InstallEvent {
            app_id: app.into(),
            app_name: format!("{} app", app),
            version: "1.0".into(),
            installed_at: Utc::now(),
            source,
            installer_path: None,
            required_admin: false,
            file_count: 100,
            total_bytes: 10_000_000,
            signed,
            signer: if signed { Some("Trusted Inc".into()) } else { None },
        }
    }

    #[test]
    fn test_unsigned_installer_flagged() {
        let mut t = InstallTracker::new();
        let flags = t.record(event("malware", InstallSource::OfficialRepo, false));
        assert!(flags.iter().any(|f| f.flag_type == FlagType::UnsignedInstaller));
    }

    #[test]
    fn test_untrusted_source_flagged() {
        let mut t = InstallTracker::new();
        let flags = t.record(event("sketchy", InstallSource::DirectDownload, true));
        assert!(flags.iter().any(|f| f.flag_type == FlagType::UntrustedSource));
    }

    #[test]
    fn test_batch_install_detected() {
        let mut t = InstallTracker::new();
        t.record(event("a", InstallSource::OfficialRepo, true));
        t.record(event("b", InstallSource::OfficialRepo, true));
        t.record(event("c", InstallSource::OfficialRepo, true));
        let flags = t.record(event("d", InstallSource::OfficialRepo, true));
        assert!(flags.iter().any(|f| f.flag_type == FlagType::BatchInstall));
    }

    #[test]
    fn test_trusted_signer_no_flag() {
        let mut t = InstallTracker::new();
        t.trust_signer("Trusted Inc");
        let flags = t.record(event("firefox", InstallSource::OfficialRepo, true));
        assert!(!flags.iter().any(|f| f.flag_type == FlagType::SuspiciousSigner));
    }

    #[test]
    fn test_untrusted_signer_flag() {
        let mut t = InstallTracker::new();
        t.trust_signer("Trusted Inc");
        let mut e = event("shady", InstallSource::OfficialRepo, true);
        e.signer = Some("Unknown Signer".into());
        let flags = t.record(e);
        assert!(flags.iter().any(|f| f.flag_type == FlagType::SuspiciousSigner));
    }

    #[test]
    fn test_by_source() {
        let mut t = InstallTracker::new();
        t.record(event("a", InstallSource::OfficialRepo, true));
        t.record(event("b", InstallSource::DirectDownload, true));
        assert_eq!(t.by_source(&InstallSource::OfficialRepo).len(), 1);
    }

    #[test]
    fn test_total_bytes() {
        let mut t = InstallTracker::new();
        t.record(event("a", InstallSource::OfficialRepo, true));
        t.record(event("b", InstallSource::OfficialRepo, true));
        assert_eq!(t.total_bytes(), 20_000_000);
    }

    #[test]
    fn test_recent() {
        let mut t = InstallTracker::new();
        t.record(event("a", InstallSource::OfficialRepo, true));
        assert_eq!(t.recent(7).len(), 1);
    }

    #[test]
    fn test_risk_scores() {
        assert!(InstallSource::DirectDownload.risk_score() > InstallSource::OfficialRepo.risk_score());
        assert!(InstallSource::Unknown.risk_score() > 0.7);
    }

    #[test]
    fn test_admin_required() {
        let mut t = InstallTracker::new();
        let mut e = event("sudo_app", InstallSource::OfficialRepo, true);
        e.required_admin = true;
        t.record(e);
        t.record(event("normal", InstallSource::OfficialRepo, true));
        assert_eq!(t.admin_required().len(), 1);
    }
}
