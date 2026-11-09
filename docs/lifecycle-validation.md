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
  -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 --entrypoint python \
  ghcr.io/home-assistant/home-assistant:2026.10.4 \
  tests/api_profiles/check_lifecycle_homeassistant.py
```

The image must already be installed (`--pull never`); the checker does not
install requirements. The validation environment can additionally mount its
existing test dependencies read-only at `/deps` with `PYTHONPATH=/deps:/src` and
`COVERAGE_CORE=pytrace` when running pytest. Select individual checks with repeated
`--case registry`, `--case ambiguous`, `--case ambiguous-device`, `--case options`, `--case authentication`,
`--case concurrency`, `--case same-station`, or `--case mixed-owners` arguments.
JSON is written to stdout; HA diagnostics and assertion tracebacks go to stderr.
Any regression or attempted network access exits nonzero. Both same-station cases
must pass the actual coexistence contract below; a known collision is not success.

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
production reader raises `APIAuthRejectedError`, a subtype of `APIAuthError`.
One automatic session renewal is allowed. Only an affirmative rejection during
that attempt becomes `ConfigEntryAuthFailed`: required-reader HTTP 401/403 or the
existing EU5 invalid-credentials code 406 after both login modes. HA then starts
one non-CAPTCHA reauth flow and stops scheduled polling. Optional 403 handling is
unchanged and is never marked as affirmative required-endpoint rejection.

**The broad `APIAuthError` is not proof of permanent failure.** JP5/LA5 login
503/429, malformed login replies, missing redirects/cookies, EU5 malformed pubkey
JSON and ambiguous HTML/auth-page heuristics remain retryable `UpdateFailed`
after the bounded renewal attempt. No regional request ordering is changed.
Unknown login/protocol failures are deliberately not promoted to permanent
credential rejection. The existing CAPTCHA sequence remains unchanged.

Twelve synthetic renewal cases invoke the real JP5/LA5/EU5 login methods with
only HTTP replies substituted. They cover login 503/429/non-JSON/timeout,
JP5 redirect 503/429, LA5 missing redirect and EU5 pubkey 503/429/non-JSON. The
actual-HA checker verifies one reset/renewal, no reauth flow, scheduled polling
retained, later recovery and stable IDs for each case. A transient required-fetch
timeout separately makes two fetch attempts with zero re-logins. These are
protocol-failure regressions, not actual account authentication verification.

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

## Same station, two accounts: supported identity contract

Two accounts may legitimately access the same plant. Both entries are admitted;
users may disable unwanted devices through HA. API telemetry keys are unchanged.
HA identities are resolved separately by `identity.py`:

- The existing registry owner retains its legacy namespace. Secondary entries use
  the immutable config-entry ID (`__entry_<entry_id>`), not username, host, account
  DN, load order or an ephemeral `_2`. HA may still suffix displayed entity IDs.
- A persistent `ha_identity` record is saved using `async_update_entry` for every
  relevant station entry, including disabled/unloaded entries, before sensor
  registration. Assignment has no await points. Existing registry ownership wins
  over config-entry age; a disabled older entry cannot displace a registered owner.
- Legacy ownership is per entity. A partially discovered historical 143/1 split
  preserves all 144 old unique IDs, entity IDs, config-entry owners and device IDs;
  only the missing counterparts receive scoped IDs. Exceptions are persistent and
  never promoted to newly-free legacy IDs after the other account is removed.
- Secondary device identifiers are updated **in place** through DeviceRegistry,
  preserving registry IDs, entity associations, user metadata and parent IDs.
  Plant, inverter/canonical DN, meter, battery/module, cluster and optimizer
  identifiers and parent lookups share the same scope. HA 2026.10.4 already keeps
  devices per config entry even when old identifiers overlap.
- Ordinary sensors, both forecast entities and native Recorder source resolution
  use one identity resolver. Recorder additionally verifies config-entry ownership;
  a missing/wrong owner fails closed rather than reading another account's history.
- Battery-primary restoration understands scoped registry IDs. Legacy inverter
  telemetry in a coexisting entry is aliased to its existing registry unique ID,
  not renamed; the single-entry inverter migration remains unchanged.
- Metadata persistence and device migration are idempotent; a reload finishes a
  partially updated device registry. Equivalent identity bookkeeping does not
  reload another account; changed effective resolver settings do reload it, so a
  formerly ignored counterpart can attach without a restart. Credentials/options
  updates retain normal reload behavior.

The standalone `same-station` case requires **144 entities and 7 devices per
account**, disjoint entity unique IDs and device identifiers, correct owned
physical parents and Recorder sources, preservation of the first entry, reverse
reload, synthetic reauth with username change, options reload, fresh HA storage
loads and removal of either account. The `mixed-owners` case first reproduces
old 143/1 registration through ordinary HA platform APIs (temporarily disabling
only the new assignment helper), then enables migration and requires 144/144,
unchanged historical identities/user metadata/device IDs, migration with the other
account still loaded, reverse reload, fresh HA and no legacy promotion on removal.
A separate actual-HA case freezes a disabled/unloaded account before enabling it. No internal storage files are edited.

These checks are offline, synthetic authentication/HTTP fixtures on actual HA
2026.10.4, not live-account or cloud-authentication validation. Other topology
families remain covered by the existing offline/unit fixtures; this is not a
proof of every historical registry layout or crash interleaving. Different-station
installations and seven-profile offline coexistence retain their existing IDs.
No energy values/classes, parsers, cadence, auth protocol or forecast algorithm is
changed by this identity layer.

### Historical b18/b19 evidence, before the identity fix

The original b18/b19 characterization admitted two different fictional usernames
for the same fictional station. Although config-entry unique IDs included username,
discovered sensor unique IDs contained station/device scope but not account scope.
The checker then recorded overlap and actual registry ownership/entity counts.
HA 2026.10.4 created distinct devices per config entry; that alone did not make
sensor unique IDs account-isolated.

In the disposable HA 2026.10.4 run, both entries reached loaded state. The first
retained 144 registered entities; the second registered **zero** entities. Their
142 API-discovered unique IDs overlapped and remained owned by the first entry;
HA logged duplicate-ID rejections. Device counts were 7 and 1 respectively (the
second entry's installation device exists, but ignored sensors did not create
its child devices). This is a demonstrated bug/unsupported configuration, not
successful same-station coexistence.

That historical checker reported `characterized_bug_decision_needed` and an overall
`passed_with_known_collision`; those old results must not be reinterpreted as a
successful coexistence test. The subsequently approved support/migration contract
above replaces the pending policy decision, not the historical evidence.
Distinct-station coexistence remains independently exercised by
`check_runtime_homeassistant.py --coexistence`.
