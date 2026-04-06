//! # PlausiDen AppGuard — App Usage & Permission Auditing
//!
//! Tracks which applications access what data, alerts on suspicious
//! permission usage, and archives unused apps (like Android's auto-archive).
//!
//! Cross-platform: Linux (desktop entries + /proc), macOS (launchd + TCC.db),
//! Windows (registry + AppX), Android (PackageManager), iOS (entitlements).

pub mod access_log;
pub mod app_inventory;
pub mod archiver;
pub mod autostart;
pub mod data_attribution;
pub mod data_flow;
pub mod compliance;
pub mod battery;
pub mod alert;
pub mod network_acl;
pub mod network_audit;
pub mod permission_audit;
pub mod permissions;
pub mod policy;
pub mod policy_engine;
pub mod sandbox;
pub mod sandbox_evaluator;
pub mod sandbox_profiles;
pub mod process_monitor;
pub mod process_tree;
pub mod quarantine;
pub mod reporter;
pub mod resource_monitor;
pub mod risk_score;
pub mod tracker;
pub mod update_tracker;
pub mod usage_stats;

pub use autostart::{AutostartEntry, AutostartKind, AutostartManager};
pub use permissions::{Permission, PermissionAudit};
pub use process_monitor::{ProcessMonitor, RunningProcess};
pub use reporter::{AppGuardReport, AppGuardReporter};
pub use tracker::{AppUsage, UsageTracker};
