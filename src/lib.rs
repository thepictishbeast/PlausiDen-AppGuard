//! # PlausiDen AppGuard — App Usage & Permission Auditing
//!
//! Tracks which applications access what data, alerts on suspicious
//! permission usage, and archives unused apps (like Android's auto-archive).
//!
//! Cross-platform: Linux (desktop entries + /proc), macOS (launchd + TCC.db),
//! Windows (registry + AppX), Android (PackageManager), iOS (entitlements).

pub mod archiver;
pub mod permissions;
pub mod tracker;

pub use permissions::{Permission, PermissionAudit};
pub use tracker::{AppUsage, UsageTracker};
