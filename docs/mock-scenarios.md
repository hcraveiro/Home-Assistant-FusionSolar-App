# Offline API response profiles and replay tests

## Interactive developer mock mode (real HA devices/entities)

The integration can now run a **separate MOCK config entry** using predefined
HTTP responses instead of FusionSolar. This is opt-in developer functionality;
ordinary account entries keep their normal backend even when it is enabled.

1. Copy the self-contained runtime profiles from `tests/fixtures/runtime_profiles/`
   to a developer-only directory, for example `/config/fusion_solar_mock_profiles`.
2. Set `FUSIONSOLAR_DEV_PROFILE_DIR=/config/fusion_solar_mock_profiles` in the HA
   process/container environment, then restart **only the development HA**.
3. In **Settings → Devices & Services → Add Integration → Fusion Solar App**, choose
   **Offline replay (development only)** and select the profile. It asks for no
   credentials. An additional entry named **MOCK — …** is created alongside, not
   instead of, any real account entry.
4. Inspect its actual devices, entities and states on the integration page. Normal
   polling and the entry's Reload action continue to use canned responses.

For Docker Compose, add this only to the development `homeassistant` service:

```yaml
environment:
  TZ: Europe/Lisbon
  FUSIONSOLAR_DEV_PROFILE_DIR: /config/fusion_solar_mock_profiles
```

Initial runtime profiles:

| Profile | Actual HA registration verified on 2026.10.4 |
|---|---|
| `isitepower-mains-import` | Mixed issue #101 written-report fields plus synthetic runtime completion. Actual HA 2026.10.4 registers **2 devices / 73 entities** and verifies **0.64 kW import**, no export inference, stable IDs on refresh/reload/unload/setup. Missing readings stay unavailable (API `None`), not zero. |
| `single-battery-config-denied` | 1 installation, 1 inverter, 1 battery: **3 devices / 81 entities**. Optional configuration is HTTP 403; core telemetry remains available. |
| `two-inverters-two-batteries` | 1 installation, 2 inverters, 2 separately owned batteries, 2 optimizers: **7 devices / 144 entities**. Includes forced-charge power, duration and energy and daytime optimizer temperature. |

Counts include the two native forecast entities. On a development HA with Recorder
but no useful mock production history, those two derived forecasts may be
`unknown`, with the existing “no useful deltas” forecast warning. The replayed
API sensors should still have the expected values. Static profiles intentionally
do not invent a solar-production history to manufacture a forecast.

These are static repeatable HTTP profiles, **not** coherent recorded installations
or an interactive charge/discharge simulator. Rich-profile topology and sampling
are synthetic; selected configuration/detail values come from sanitized captures.
The `MOCK_RUNTIME_*` station/device identities and explicit MOCK device names
prevent registry overlap with real accounts. Do not use mock entities in real
control automations or the Energy dashboard: the development Recorder may retain
fictional history/statistics, just as it does for any ordinary HA entity.

Each mock instance has its own network-incapable session. No HA-wide requests or
socket monkeypatch is installed. Only known read-only operations against
`https://example.invalid` can match a route. Synthetic authentication is explicit;
real authentication is not replayed. A missing opt-in, missing profile, changed
station identity, unmatched request or forbidden write fails closed: it never
switches a mock entry to real login/network access.

To disable, remove only the MOCK entries through the HA UI first, then unset the
environment variable and restart the development HA. Removing the profiles or
opt-in while entries remain configured deliberately leaves those entries unable
to load; it must not turn them into real-account entries.

### Actual HA lifecycle verification

```sh
docker run --rm --pull never --network none --read-only --tmpfs /tmp \
  -v "$PWD:/src:ro" -w /src --entrypoint python \
  ghcr.io/home-assistant/home-assistant:2026.10.4 \
  tests/api_profiles/check_runtime_homeassistant.py
```

This starts a minimal **actual HA runtime** in an ephemeral configuration, without
an HTTP server or any real account. It drives the real config flow → integration
setup → coordinator → complete production `get_devices()` → sensor platform →
device/entity registries and HA state machine. It checks profile topology,
corrected values/units/icons, refresh, reload, unload/setup and stable IDs, with
zero external network attempts. It is distinct from the class-only smoke check
below. UI rendering, Recorder statistics, vendor authentication, dynamic topology
and real hardware behavior still require their own validation.

## Focused offline replay tests

`tests/api_profiles/` replays sanitized JSON profiles from
`tests/fixtures/api_profiles/` through the **real** API transport decoder,
discovery stages, battery/optimizer readers and `FusionSolarSensor` classes.
There is no production mock option and no need for FusionSolar credentials.

```sh
python -m pip install -r requirements-test.txt
python -m pytest -q tests/test_api_profiles.py tests/test_api_profile_privacy.py
```

These tests are included in the existing complete-suite CI command. The HTTP
boundary is replaced with genuine `requests.Response` objects, not precomputed
sensor values. Requests must match the frame's ordered method, path, query and
JSON body. Only `https://example.invalid` is accepted, with no network fallback
(even after a session replacement). Only two explicitly allowlisted read-only
optimizer POST endpoints are permitted. Configuration writes and login requests
are rejected. Unexpected requests are recorded and asserted after each frame,
because optional readers can otherwise catch and hide an assertion failure.

A minimal route looks like this:

```json
{
  "method": "GET",
  "path": "/rest/pvms/web/device/v1/deviceExt/get-config-signals",
  "params": {"dn": "MOCK_BAT_A"},
  "json": null,
  "status": 200,
  "body_file": "responses/forced-charge-duration.json"
}
```

Profiles have `schema_version`, `origin`, `source_url`, `description`, and named
`frames` containing routes. Tests explicitly advance frames and expire optional
configuration caches; no real-time waits or device commands are needed. Responses
are local bodies, inline or referenced with `body_file` beneath the fixture root.
Only the `_` cache-busting query parameter may be explicitly ignored.

## Implemented profiles

| Profile | Provenance | Verified behavior |
|---|---|---|
| `single-battery-config-denied.json` | Synthetic | Real flow/discovery and battery/module/pack readers; optional HTTP 403 does not erase core telemetry or expire login; legacy primary ID and inverter association. |
| `two-inverters-two-batteries.json` | Synthetic | Separate battery per inverter; real v2/v3 discovery stages and parent lookup; independent SoC values, scoped secondary IDs, correct device parents and restoration of primary context. |
| `optimizers-transitions.json` | Synthetic | Real optimizer layout, sampling and details readers; day → offline → missing → recovery; W-to-kW conversion, unavailable instead of stale readings, stable identity and parent association. |
| `optimizers-observed-day.json` | Mixed | Curated daytime `optimizer-info` excerpt from issue #47, with synthetic topology/sampling. Name, position and temperature reach the real sensor class. Sampling power is synthetic and is **not** claimed to reproduce the recorded site. |
| `forced-charge-observed.json` | Mixed | Curated [issue #47 Duration-mode response](https://github.com/hcraveiro/Home-Assistant-FusionSolar-App/issues/47#issuecomment-6628911985): `3.030 kW`, `1440 min`, `1.750 kWh`. Real parsing, corrected name/icon, stable legacy energy ID, hourly caching and synthetic HTTP 403 → recovery. The captured remaining-time field is deliberately not exposed as a live countdown. |

The response excerpts' [provenance and sanitization notes](../tests/fixtures/api_profiles/responses/README.md)
state exactly what was retained, removed or replaced. A synthetic topology based
on a valid payload shape does **not** become evidence that a real installation
behaves that way. The latest captured master-battery response does not prove the
slave battery returns identical fields.

## Coverage boundaries and missing scenarios

The five focused replay profiles exercise real flow fetching, DN/parent discovery,
battery/optimizer assembly and sensor properties/update methods, with lightweight
HA/coordinator pytest stubs. The two **runtime** profiles and lifecycle checker
above additionally exercise complete `get_devices()`, real config entries,
coordinator updates, platforms, registries and states. Neither layer claims
vendor login, Recorder/statistics, UI rendering or real hardware validation.

Existing focused regression tests cover additional cases (battery registry
restoration, third-battery discovery, optimizer ownership, authentication,
iSitePower-M, coordinator lifecycle and energy totals). Keep these tests: a case
covered there is not automatically covered by a persisted replay profile.

| Missing profile / evidence | Next useful contribution |
|---|---|
| Current dev installation: raw API baseline | Fresh sanitized response bodies are still needed. Inspection of its 137 live HA sensor states is useful runtime validation, **not** a recording of underlying HTTP responses. Never export its authentication/session data. |
| Forced **discharge** | Await a sanitized response from someone already using the mode normally. Do not infer discharge-specific power/energy signal IDs from the charge sample. |
| **Energy** setting mode | Need actual conditional fields, units and presence/absence/null behavior; Duration mode does not establish these. |
| Multiple batteries on the **same inverter** | A new topology/response profile, distinct from one battery per inverter. Verify ownership and aggregate versus per-battery metrics. |
| Late third battery / changed discovery order / ambiguous legacy primary | Ordered discovery frames asserting existing IDs stay assigned correctly and new entities do not duplicate old ones. Focused unit tests already cover these, but no complete replay profile yet. |
| Stop mode and mode changes | Captured mode-specific payloads plus clearly synthetic transitions; current failure/recovery profiles are not evidence of real mode transitions. |
| Optimizer conflicting or unknown inverter ownership | Captured ownership/topology if available, then adversarial synthetic mismatches. Current replay covers valid ownership; rejection cases remain in focused tests. |
| Independent optional versus core endpoint failures | Expand beyond configuration 403 and missing optimizer sampling: malformed data, 418, timeout, required failure and genuine authentication expiry. |
| iSitePower-M export / idle | [Issue #101 report](https://github.com/hcraveiro/Home-Assistant-FusionSolar-App/issues/101#issuecomment-6650661460) confirms matching selected v2/v3 fields during **nonzero import only**. Runtime profile retains those reported fields with explicit synthetic completion, not a raw capture. Reverse, idle and conflicting directions remain unknown; actual export/idle captures are still needed. Endpoint remains v2. |
| EU / other regions / authentication | Sanitized redirect/envelope shapes, expiry and recovery, with fictional tokens only; current profiles bypass login. |
| Dynamic runtime / Recorder / UI | Static registration and refresh/reload/unload now pass in actual HA. Still add live topology changes, unavailable/recovery transitions, Recorder/statistics assertions and UI rendering checks. |

## Actual Home Assistant class smoke check

For the fields absent from our real dev account, there is an additional checker:

```sh
docker run --rm --pull never --network none --read-only --tmpfs /tmp \
  -v "$PWD:/src:ro" -w /src --entrypoint python \
  ghcr.io/home-assistant/home-assistant:2026.10.4 \
  tests/api_profiles/check_homeassistant.py
```

The image must already be present locally (`--pull never`). This runs a **separate,
offline process with real Home Assistant libraries**, not pytest stubs and not
the running HA dev server. It instantiates actual sensor classes and checks the
forced-charge power, duration and energy plus optimizer power, temperature and
name. It does not start HA, register entities, write registries/states, or change
the real account. It is a metadata/value smoke check, **not full HA E2E**.

## Adding captures and profiles safely

Label provenance explicitly:

- **Observed:** a minimized, sanitized response actually captured/published, with
  its source and limitations. Do not label invented fields observed.
- **Synthetic:** constructed topology, payload, error or transition. Explain the
  assumption; it is not evidence of backend behavior.
- **Mixed:** observed excerpts combined with synthetic topology or transitions;
  identify each part.

Never commit raw HAR files, auth headers, cookies, CSRF/SSO tokens, credentials,
personal information, real station IDs, device DNs or serial numbers. Extract
minimal response bodies; whitelist fields and replace identifiers consistently
across parent/child references. Review nested fields, URLs and error messages.
Privacy tests guard the curated excerpt corpus, but do not replace human review.

**Do not change battery operation to obtain samples.** Ask contributors only for
sanitized read responses from modes they already use normally. No forced
charge/discharge activation, mode switches or stopping operation for testing.
Missing evidence remains a catalog gap; simulate failures/offline transitions
locally instead of provoking them on real hardware.

1. Choose a gap and document source/provenance before adding data.
2. Sanitize locally and include only the minimal response fields needed.
3. Add a profile with explicit frames/routes and assertions on values, units,
   IDs/parents and recovery. Never bypass the strict no-network transport.
4. Run the profile/privacy tests and complete suite; run the actual-HA smoke
   checker where available.
5. Update the catalog only for behavior actually verified. Keep missing evidence
   and full-runtime validation limitations visible.
