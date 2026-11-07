# Curated response excerpts

These are response **bodies**, not HAR recordings. No request headers, cookies,
session tokens, URLs containing installation IDs, account information, or real
serial numbers are included. Profiles using them must state their provenance.

| File | Source | Changes / limits |
|---|---|---|
| `forced-charge-duration.json` | [Issue #47, 2026-11-04](https://github.com/hcraveiro/Home-Assistant-FusionSolar-App/issues/47#issuecomment-6628911985), master-battery `get-config-signals` response during an already-running forced charge | Device Information group removed; configuration fields reduced to IDs, names, values, units, types, display/edit/rights flags and enumerations. Values and signal IDs retained. No discharge-mode response, no evidence that the other battery returns identical data. |
| `optimizers-day.json` | Daytime HAR previously supplied for [issue #47](https://github.com/hcraveiro/Home-Assistant-FusionSolar-App/issues/47), `layout/optimizer-info` | First two records retained from an eight-record response; field allowlist only. DNs, parent DN, serials, names and positions replaced with consistent `MOCK_*` identifiers/names. Electrical values and temperature preserved. The associated topology and sampling responses in profiles are synthetic, not a complete recorded site. |

A profile combining observed excerpts with fabricated topology is **mixed**, not
an observed installation. A synthetic offline/permission/recovery frame proves
our handling of that input; it does not prove the vendor always emits that shape.

Remaining time is intentionally retained in the forced-charge excerpt even though
it is not exposed as a live sensor: the configuration endpoint is cached hourly.
This lets tests guard against accidentally treating a cached countdown as live.
