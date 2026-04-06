//! # PlausiDen AppGuard — App Usage & Permission Auditing
//!
//! Tracks which applications access what data, alerts on suspicious
//! permission usage, and archives unused apps (like Android's auto-archive).
//!
//! Cross-platform: Linux (desktop entries + /proc), macOS (launchd + TCC.db),
//! Windows (registry + AppX), Android (PackageManager), iOS (entitlements).

pub mod archiver;
pub mod autostart;
pub mod data_flow;
pub mod compliance;
pub mod network_audit;
pub mod permissions;
pub mod policy;
pub mod sandbox;
pub mod process_monitor;
pub mod reporter;
pub mod tracker;

pub use autostart::{AutostartEntry, AutostartKind, AutostartManager};
pub use permissions::{Permission, PermissionAudit};
pub use process_monitor::{ProcessMonitor, RunningProcess};
pub use reporter::{AppGuardReport, AppGuardReporter};
pub use tracker::{AppUsage, UsageTracker};
