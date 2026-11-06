# Disposable actual-HA lifecycle validation

`tests/api_profiles/check_lifecycle_homeassistant.py` is a standalone checker,
not a pytest test and not a live-HA test. It imports the installed Home Assistant
2026.10.4 classes, integration package, flow managers, sensor platform, registries,
service authorization and executor jobs. The ordinary pytest suite's HA-shaped
fixtures are not imported.

## Safety and reproduction

Use only a disposable container. No existing HA configuration is mounted, no
ports are exposed, and no credentials or Huawei servers are used:

```sh
docker run --rm --pull never --network none --read-only --tmpfs /tmp \
  -v /path/to/checkout:/src:ro -w /src \
  -e PYTHONDONTWRITEBYTECODE=1 --entrypoint python \
  ghcr.io/home-assistant/home-assistant:2026.10.4 \
  tests/api_profiles/check_lifecycle_homeassistant.py
```

The image must already be installed (`--pull never`); the checker does not
install requirements. The validation environment can additionally mount its
existing test dependencies read-only at `/deps` with `PYTHONPATH=/deps:/src` and
`COVERAGE_CORE=pytrace` when running pytest. Select individual checks with repeated
`--case registry`, `--case ambiguous`, `--case ambiguous-device`, `--case options`, `--case authentication`,
`--case concurrency`, or `--case same-station` arguments. JSON is written to
stdout; HA diagnostics and assertion tracebacks go to stderr. Any regression or
attempted network access exits nonzero. `same-station` deliberately reports a
known collision as `characterized_bug_decision_needed`, **not** as fixed.

All test identities are fictional `MOCK_RUNTIME_` values. An `OfflineSession`
without network adapters handles every data request; independent TCP, DNS and
Requests transport guards record attempted escapes, including attempts swallowed
by optional readers. The Docker network is disabled as a second boundary. All
configuration and registry stores live exclusively in container `/tmp` and are
destroyed on exit. Registry/config-entry APIs and HA's normal shutdown/load own
persistence; the checker does not read or edit internal storage files directly.

Production polling intervals, historic-reader pacing, numeric normalization,
energy classes and IDs are not changed by the checker. The concurrency retry-gap
test replaces only the coordinator's one-second retry pause with a bounded,
event-driven barrier so unload can be observed at a deterministic point. It does
not change API reader pacing or provide a performance benchmark.

## Covered assertions

### Registry migration and fresh storage lifecycle

A disabled actual `ConfigEntry` is added through `ConfigEntries.async_add` before
setup. Official device/entity/area/label registry APIs seed legacy inverter and
battery telemetry. Secondary devices are registered first; legacy telemetry
belongs to inverter B and primary battery B, not the first flow node.

The checker enables the entry through HA, runs production setup/migration and
sensor registration, unloads/setups again, stops HA normally to flush its stores,
and constructs a **new `HomeAssistant`** against the same temporary directory.
The second instance loads its config entries and registries normally and repeats
setup/unload/setup. Assertions cover:

- unambiguous inverter unique-ID migration to inverter B's existing scoped ID;
- retention of entity ID, registry ID, owning config entry and device association;
- retention of user name, icon, area, label, hidden and disabled settings,
  original creation timestamp, and device user-name override;
- primary battery B restoration and persistence, independent of device/flow order;
- orphan legacy inverter/battery entities remain unchanged when ambiguous;
  scoped battery telemetry remains possible, but no arbitrary primary is chosen;
- a legacy inverter associated with an actual device carrying two inverter DN
  identifiers is not reassigned by arbitrary set/identifier iteration order;
- identity retention across unload/setup and the fresh-HA/storage lifecycle.

This is a targeted migration fixture, not every possible historical registry
layout or a real user's database.

### Account-branch options and synthetic reauth

The checker runs the ordinary account config flow with **no mock marker**. Only
API construction is replaced by a network-incapable `OfflineAccountAPI` subclass
of the existing runtime mock. Config-flow validation, station selection, token
transfer/cleanup, coordinator construction, setup, platforms, options manager,
update listener and actual entry reload remain production paths.

**Authentication is synthetic, not actual-auth verified.** No real login,
CAPTCHA, regional endpoint or Huawei account is validated. This does not establish
that issues #44 or #111 are fixed.

Options checks save valid 180/240-second scan intervals, toggle native → Solcast
→ native, reject an unknown provider through HA's selector validation, and reject
missing/malformed Solcast source entities through the integration's source check.
Invalid choices must not mutate persisted options or reload. Valid choices must
replace/close the old coordinator API, apply the selected builder/interval, remove
the stale Solcast source when returning to native, and retain registry identities.
The local Solcast-shaped source is fictional; no Solcast integration is installed.
Native Recorder forecast accuracy/history is outside this checker.

Required HTTP 401 responses are injected at the offline session boundary, so the
production HTTP reader raises `APIAuthError`. One automatic session renewal is
allowed. A second auth rejection (from login or the required fetch) must remain
`ConfigEntryAuthFailed`, allowing HA's actual coordinator to start one non-CAPTCHA
reauth flow and stop scheduled polling. A transient timeout still makes exactly
two required fetch attempts, with no session reset/login or reauth, and recovers
on a later successful refresh. Data-structure/other retry failures remain
`UpdateFailed`; the existing CAPTCHA sequence is unchanged.

### Concurrency, unload and authorization

Three batches overlap actual refreshes, debounced refresh requests, and serialized
scenario service advance/reset calls. A deterministic HTTP timeout/retry barrier
then overlaps an in-flight refresh with actual platform unload/coordinator
shutdown/API close. Assertions require unload to wait before closing transport,
then complete without deadlock, reject scenario calls while shutdown is waiting,
remove runtime/service resources, perform no I/O on a subsequent shutdown refresh,
and retain identities on fresh setup. Scenario calls racing with API close are
translated to a normal `HomeAssistantError` rather than leaking transport errors.

The nonadmin test creates actual local HA auth users, passes a real
`Context(user_id=...)` to `hass.services.async_call`, and requires `Unauthorized`
before a scenario transition can be queued. No global/live service is called.
This is bounded adversarial scheduling, not a proof for every thread interleaving
or cancellation/failure at every await point.

## Same station, two accounts: decision needed

The ordinary account flow admits two different fictional usernames for the same
fictional station. Although config-entry unique IDs include username, discovered
sensor unique IDs contain station/device scope but not account scope. The checker
records the overlap and actual registry ownership/entity counts after both setups.
HA 2026.10.4 creates distinct devices per config entry; that alone does not make
sensor unique IDs account-isolated.

In the disposable HA 2026.10.4 run, both entries reached loaded state. The first
retained 144 registered entities; the second registered **zero** entities. Their
142 API-discovered unique IDs overlapped and remained owned by the first entry;
HA logged duplicate-ID rejections. Device counts were 7 and 1 respectively (the
second entry's installation device exists, but ignored sensors did not create
its child devices). This is a demonstrated bug/unsupported configuration, not
successful same-station coexistence.

No IDs are silently rewritten and no new admission policy is introduced here.
Maintainers must separately choose whether multiple accounts for the same station
are supported, rejected, or share one canonical setup, and define any migration
before changing released IDs. Distinct-station coexistence is a different case
already exercised by `check_runtime_homeassistant.py --coexistence`.
