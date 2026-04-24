# PlausiDen-AppGuard — SCOPE (RENAMING NOTICE)

> **The existing code in this directory is being renamed to AppTracker.**
> See `/home/user/Development/PlausiDen/PlausiDen-AppTracker-CHARTER.md`.
>
> **"AppGuard" is a NEW, separate product** — described below. It will
> live in a new directory when created. The current README at the top
> of this repo describes AppTracker's behavior, not the new AppGuard.

## Charter for the new AppGuard
User directive 2026-04-19: *"another project should be called AppGuard
that provides lightweight security for Linux and others that uses
AppTracker to get intel."*

## Identity (new)
- Short name: **AppGuard**
- Long name: **PlausiDen-AppGuard**
- Tagline: *Lightweight endpoint security for Linux (and others), driven by AppTracker intel.*

## Scope (what the new AppGuard DOES)
- **Endpoint-level app security.** Lightweight — not an EDR, not a
  full AV. Focused on:
  - Kill / quarantine / sandbox individual apps flagged high-risk
    by AppTracker.
  - Enforce per-app network / filesystem / capability rules.
  - Rate-limit background activity (the "this app runs hot at 3am"
    anomaly).
  - Signature / integrity check on binaries before launch.
  - Revoke permissions on apps AppTracker flagged as unused-but-
    permissioned.
- **Consumes AppTracker.** Calls AppTracker's `GET /apps/:id/risk`
  + `GET /apps/:id/permissions` to make enforcement decisions. No
  tracking logic duplicated here.
- **Linux-first, OS-neutral.** Primary target Linux (systemd unit
  hardening + landlock + seccomp + cgroup rules). Parallel stacks on
  Windows (AppLocker + WFP), macOS (Endpoint Security framework),
  Android (DeviceAdmin + AccessibilityService where possible), iOS
  (MDM hook).

## What AppGuard does NOT do
- **Does not track usage.** That's AppTracker.
- **Does not replace firewall / sentinel / vuln-scanner** — those
  live in PD Networker.
- Not a full EDR — this is the "lightweight" tier. A separate,
  heavier product could be chartered later.

## Integration surface
- Consumes: AppTracker read-only API (see AppTracker charter).
- Consumed by: PD Networker policy engine (AppGuard exposes "what's
  currently blocked / sandboxed on this host" to the dashboard).
- Consumed by: PlausiDen-DevOps incident responder (AppGuard events
  flow into incident timeline).

## Architecture sketch (future, when new repo is created)
```
PlausiDen-AppGuard-v2/      # placeholder name — user picks final
├── Cargo.toml
├── crates/
│   ├── appguard-core/      # policy engine + rule evaluator
│   ├── appguard-agent/     # runs on the host, enforces
│   ├── appguard-linux/     # landlock + seccomp + cgroup adapter
│   ├── appguard-windows/   # AppLocker + WFP adapter
│   ├── appguard-macos/     # Endpoint Security adapter
│   └── appguard-cli/       # local admin CLI
├── adapters/
│   └── apptracker/         # thin client for AppTracker API
└── README.md
```

## Directory situation (current)
- `PlausiDen-AppGuard/` exists and holds **AppTracker's code**.
- `PlausiDen-AppTracker/` does not yet exist.
- A **new** `PlausiDen-AppGuard` for the endpoint-security product
  also does not yet exist.

### Deferred migration plan (do not execute yet)
1. Rename existing dir: `PlausiDen-AppGuard/` → `PlausiDen-AppTracker/`.
2. Create new dir: `PlausiDen-AppGuard/` (fresh) for the new product.
3. Update package names, binary names, CI configs, systemd units.
4. User schedules the migration; all three Claudes run short-loop
   AVP (Tiers 1-3, six passes) post-migration.

## Monetization pointer
- Free tier: self-hosted AppGuard on any supported OS.
- Paid tier: central policy server for orgs — push a single app
  policy to 500 devices, see enforcement telemetry. $Y/device/month.
- Bundled tier: AppTracker + AppGuard + PD Networker Firewall →
  "PlausiDen Endpoint" SMB package, flat yearly price per seat.

## Related
- Master charter: `/home/user/Development/PlausiDen/PORTFOLIO_REALIGNMENT_2026-04-19.md`
- AppTracker charter: `/home/user/Development/PlausiDen/PlausiDen-AppTracker-CHARTER.md`
- PD Networker charter: `/home/user/Development/PlausiDen/PlausiDen-Networker-CHARTER.md`
