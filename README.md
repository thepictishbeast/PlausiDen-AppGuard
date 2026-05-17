> # ⚠️ DO NOT USE — UNVERIFIED — UNSAFE ⚠️
>
> This software is **unverified and unsafe for any production use**.
> It is published publicly only for transparency, third-party audit,
> and reproducibility. Treat every commit as guilty until proven
> innocent.
>
> By using this code you accept:
> - **No warranty** of any kind, express or implied.
> - **No fitness** for any particular purpose.
> - **No guarantee** of correctness, safety, or freedom from defects.
> - **Zero liability** on the maintainer for any damages — data loss,
>   security compromise, financial loss, or any consequential damages.
>
> The code is under active engineering development per the
> [Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md).
> Every commit's default verdict is **STILL BROKEN**. AVP-2 requires
> a minimum of 36 verification passes before a `SHIP-DECISION:`
> annotation may be considered. **No commit in this repository has
> reached `SHIP-DECISION:` status.**

# PlausiDen AppGuard

App usage tracking, permission auditing, and unused app archival. Tracks which apps access what data, when, and whether the user was actively using the app at the time. Archives unused apps to free space while preserving user data.

## Features

- **Usage tracking**: Launch count, foreground time, last used, usage frequency
- **Archive candidates**: Identifies unused apps sorted by reclaimable space
- **Permission auditing**: Grants vs actual usage, background access flagging
- **Risk scoring**: Rates apps by permission profile danger level
- **Archival**: Remove binary, keep data, restore on demand (like Android auto-archive)

## License

BSL 1.1 with Apache 2.0 change date of 2030-04-04.
