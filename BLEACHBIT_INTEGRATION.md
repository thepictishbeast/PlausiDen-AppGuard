# AppGuard = app inventory + last-launched tracker emitting Atrium-compatible cleaners

**Decision date:** 2026-04-26.

AppGuard is a Rust-first deterministic app inventory + usage tracker.
For each installed application, it computes:

- **Where it lives**: binary path(s), config dir(s), cache dir(s), data dir(s)
- **How big it is**: total disk cost across all of the above
- **When it was last launched**: best-effort from multiple signals
- **Whether to suggest archiving / uninstalling**

Then emits cleaner definitions as JSON matching the
[`DYNAMIC_CLEANER_SCHEMA`](https://github.com/thepictishbeast/PlausiDen-Meta/blob/main/DYNAMIC_CLEANER_SCHEMA.md).

AppGuard ships **no UI**. Atrium (a fork of BleachBit) consumes the
JSON and presents per-app cleaner entries alongside Tidy's file-rule
ones and BleachBit's stock cleaners.

## What AppGuard emits

Files at `/var/lib/atrium/dynamic-cleaners/appguard-<app>.json` (one
per application surveyed). Refreshed on each scan.

## Inventory sources

AppGuard walks every package source it can find:

| Source | How |
|---|---|
| `apt` / `dpkg` | `dpkg -l` |
| `flatpak` | `flatpak list --app --columns=...` |
| `snap` | `snap list` (when snapd present) |
| AppImage | scan known dirs + `.desktop` registrations |
| `/opt/<app>/` | enumerate top-level dirs |
| `~/.local/bin/`, `~/Applications/` | binary scan |
| systemd user units | for daemons |

## Last-launched detection (multi-signal, best-effort)

| Signal | How |
|---|---|
| Binary atime | when the OS hasn't disabled atime updates |
| `.desktop` launch hook | AppGuard registers an Exec-prefix logger that writes per-launch lines to `~/.local/share/appguard/launches.log` |
| Journal scrape | `journalctl _COMM=<binary> --since` window |
| Config mtime | weak proxy for "user changed settings" |

If multiple signals available, take max. If none, mark as `last_launch_known: false`.

## Recommendation policy (initial)

| Condition | Suggested action |
|---|---|
| > 90 days unused AND > 100 MB | suggest **archive** (tar.zst to `~/Archives/apps/`) |
| > 180 days unused AND > 500 MB | suggest **uninstall** |
| binary missing but config/cache exists (orphan) | suggest **purge orphaned data** |
| duplicate-purpose apps installed (Signal + Signal Beta, Zoom + Skype) | suggest **review which to keep** (no auto-action) |

All thresholds configurable in `appguard.toml`. Defaults are
conservative — user always confirms via Atrium's UI.

## Architecture (planned)

```
appguard-cli            → operator interface: scan / inspect / emit
appguard-core (lib)     → inventory engine + signal aggregator
appguard-emitter (lib)  → schema-compliant JSON writer
appguard-launch-hook    → small binary that wraps Exec= entries; logs every launch
appguard-watcher        → systemd timer triggering periodic scans
```

Rust crates, edition 2024.

## What AppGuard does NOT do

- **Never deletes anything.** Recommendations only. Atrium executes.
- **No file-rule logic.** That's Tidy's job.
- **No filesystem-wide scan.** AppGuard scans only known app paths;
  Tidy handles the broader filesystem.

## Privacy note

The `.desktop` launch logger writes per-launch lines (timestamp + app
name) to a local file. **No telemetry off-machine.** The log is
purely local and is itself subject to AppGuard's own
"data-retention" rule (rotated weekly, kept 90 days).

## Status

Planning. First implementation slice: appguard-cli + apt source + opt
source + binary-atime signal + first 5 emitted cleaners (Zoom-class
heavy desktop apps). Estimated 1-2 days.
