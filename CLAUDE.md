# CLAUDE.md — Instructions for Claude Code

## IMPORTANT: Read this first if context was compacted.

## Project: plausiden-appguard
App usage tracking, permission auditing, unused app archival. Cross-platform.

## Key Modules (IMPLEMENTED):
- tracker.rs: UsageTracker with launch recording, foreground time, archive candidates, usage frequency (6 tests)
- permissions.rs: PermissionAuditor with risk scoring, background access detection, unused permission identification (4 tests)
- archiver.rs: Archive/restore scaffold

## Integrates with:
- PlausiDen-Purge: cleanup after archival
- PlausiDen-Sentinel: suspicious permission alerts feed into threat detection
