# Testing and coverage

Run all tests locally with:

```bash
python -m pip install -r requirements-test.txt
python -m pytest tests -v --cov=custom_components/fusion_solar_app --cov-branch --cov-report=term-missing
```

The CI runs all `tests/test_*.py` discovered by pytest, including `unittest` tests, and fails on any failure, collection error, zero collected tests, or combined line/branch coverage below **78%**. Reports retain separate line and branch counts in `coverage.json`. It runs separate jobs with the standard-library `json` decoder and the optional `simplejson` decoder used by Requests in Home Assistant, and verifies which decoder is active.

## Numeric telemetry regressions

See [the numeric telemetry contract](../docs/numeric-telemetry.md) for accepted
units, unavailable-vs-zero policies and preserved discovery/rounding behavior.
`test_numeric_telemetry.py` exercises the actual parser and assembled API readers.
`test_periodic_energy_placeholders.py` covers the corrected b19 contract:
individual `--` is unavailable, and every calculated energy sum skips literal
markers but requires at least one valid segment. No period-specific zero exception
remains; actual zero, lifetime anomalies and existing state classes are preserved.
`api_profiles/check_numeric_homeassistant.py` adds a focused disposable actual-HA
HTTP transition check without adding a persistent eighth runtime profile.

## JSON decoding and error-log regressions

`requests.Response.json()` raises `requests.exceptions.JSONDecodeError`, whose base decoder depends on whether `simplejson` is installed. The offline replay transport uses standard-library JSON. Both error families must retain the intended auth/connection classification without swallowing unrelated programming errors.

The auth and social behavior tests exercise both exception families and real Requests responses. Installation, station and social error-path tests use synthetic session/body markers and assert that raw cookies, headers and response bodies do not enter the tested diagnostic messages. These targeted assertions do not imply that all integration DEBUG logs or upstream exception traces are anonymized; review and sanitize any support logs before sharing them.

To reproduce both environments, use a disposable test virtualenv (never modify a running Home Assistant's dependencies): run the suite once without `simplejson`, then install `simplejson>=3,<5`, verify `requests.compat.json.__name__`, and rerun it. Release validation additionally uses the actual Home Assistant container dependencies with test-only tooling mounted separately, a read-only source tree and networking disabled.

## Actual Home Assistant and Recorder checks

The **Isolated Home Assistant runtime checks** workflow runs on relevant beta-branch pushes and supports manual dispatch. It pulls the specified HA image once, then executes the standalone checkers in disposable containers with networking disabled and read-only source. Reports and stderr are uploaded even on failure; no live HA configuration, credentials or databases are mounted. The job requires no pytest installation into HA.

- Seven-profile lifecycle/coexistence and the disposable numeric/periodic-energy checker exercise actual HA entries, registries and states.
- [Recorder validation](../docs/recorder-validation.md) compiles real short-term and hourly statistics using a temporary SQLite database. It verifies that b19's individual `--` → unavailable avoids the artificial zero/recovery overcount demonstrated under the mistaken b17/b18 policy. A passing characterization **does not mean all statistical risks are fixed**: partial aggregates and large downward corrections can still cross HA's reset threshold. Sensor classes and existing history are not altered.
- [Lifecycle validation](../docs/lifecycle-validation.md) exercises persisted registries across fresh HA instances, options/provider reloads, reauth, concurrent shutdown and real service authorization. It deliberately reports `passed_with_known_collision`: two accounts admitted for the same station still collide in station-scoped unique IDs. This is characterized, not a new admission or identity policy.
- [Forecast performance validation](../docs/performance-validation.md) compares the complete b17 and candidate builder outputs, persistence, query bounds/work and cancellation under actual HA with deterministic Recorder/Store seams. It is not a real-database throughput benchmark. The comparison baseline is read from the published b17 source in git history.

GitHub branch protection is configured separately and is not changed by these workflows.

## Historical coverage milestones

The milestones below document earlier development, not the current test count or coverage. See the latest release validation for current measurements.

**Initial measurement:** 23 passing tests and approximately **3%** overall integration line coverage at the initial PR #60 baseline; improved to **6.65%** with the behavioral tests in PR #61 on Python 3.13. The 78% minimum is a regression guard, **not** an adequate final production-quality target. It should be increased with additional behavioral tests, especially authentication, CAPTCHA, session renewal, installation discovery, sensor state and config flows. Most existing tests compile selected functions from AST nodes rather than importing and exercising the running integration; consequently coverage is low despite green tests.

`coverage.xml` and `test-results.xml` are uploaded by the workflow to support further reporting. GitHub branch protection must separately require both **PV discovery regression tests (json)** and **PV discovery regression tests (simplejson)** checks on `main` if merging should be blocked by failing CI.

**PR #62 baseline:** 85 passing tests, 15.10% measured overall line coverage on Python 3.13. Tests now exercise installation flow parsing, partial device discovery, battery detection, social contribution, and energy balance calculations.

**PR #63 milestone:** 138 tests passed and 31.11% measured overall line coverage. New behavioral tests cover battery, inverter, power meter, and station discovery, telemetry parsing, KPI fallbacks, entity assembly, and response errors.

**PR #64 milestone:** More than 50% total line coverage via tests of assembled API session lifecycle, full energy aggregation, Native forecasting, and Solcast forecast interpolation. Coverage uses all production modules as its denominator. Home Assistant integration and coordinator scenarios remain follow-up priorities.

**PR #71 milestone:** 270 tests passed with 70.17% overall line coverage on Python 3.13. Added tests running actual coordinator polling/recovery, Home Assistant sensor properties/device metadata, forecast chart transformations, native forecast history processing, midnight cache invalidation, smoothing, and forecast generation. Home Assistant interfaces and Huawei HTTP calls are mocked; these complement rather than replace live beta validation.\n

**PR #74 milestone:** 278 passing tests, 71.47% line coverage. Production Home Assistant entry lifecycle now has 100% line coverage (setup, session persistence cleanup, initial failure handling, options reload, unload success/failure). No runtime changes.\n

**PR #75 milestone:** 299 tests passing with 76.95% integration line coverage. Real Config Flow functions are exercised with mocked Home Assistant/HTTP boundaries: login errors, CAPTCHA, station selection, session update/reload, reconfiguration guards, and Solcast/native options. Config Flow line coverage reaches 67%. No runtime changes.


**PR #77 milestone:** 310 passing tests plus one strict expected failure, 78.68% overall line coverage. New production-method tests cover CAPTCHA reauthentication/reconfiguration, dynamic PV sensor discovery and identity deduplication, and forecast cache invalidation at midnight or when a source changes. Known pre-existing issue: a failed station-list fetch after accepted CAPTCHA currently displays `invalid_captcha` rather than `cannot_connect`; preserved as `xfail(strict=True)` pending a separate functional fix. No production changes.
