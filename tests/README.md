# Testing and coverage

Run all tests locally with:

```bash
python -m pip install -r requirements-test.txt
python -m pytest tests -v --cov=custom_components/fusion_solar_app --cov-report=term-missing
```

The CI runs all `tests/test_*.py` discovered by pytest, including `unittest` tests, and fails on any failure, collection error, zero collected tests, or overall coverage below **76%**.

**Initial measurement:** 23 passing tests and approximately **3%** overall integration line coverage at the initial PR #60 baseline; improved to **6.65%** with the behavioral tests in PR #61 on Python 3.13. The 76% minimum is a regression guard, **not** an adequate final production-quality target. It should be increased with additional behavioral tests, especially authentication, CAPTCHA, session renewal, installation discovery, sensor state and config flows. Most existing tests compile selected functions from AST nodes rather than importing and exercising the running integration; consequently coverage is low despite green tests.

`coverage.xml` and `test-results.xml` are uploaded by the workflow to support further reporting. GitHub branch protection must separately require the **PV discovery regression tests** check on `main` if merging should be blocked by failing CI.

**PR #62 baseline:** 85 passing tests, 15.10% measured overall line coverage on Python 3.13. Tests now exercise installation flow parsing, partial device discovery, battery detection, social contribution, and energy balance calculations.

**PR #63 milestone:** 138 tests passed and 31.11% measured overall line coverage. New behavioral tests cover battery, inverter, power meter, and station discovery, telemetry parsing, KPI fallbacks, entity assembly, and response errors.

**PR #64 milestone:** More than 50% total line coverage via tests of assembled API session lifecycle, full energy aggregation, Native forecasting, and Solcast forecast interpolation. Coverage uses all production modules as its denominator. Home Assistant integration and coordinator scenarios remain follow-up priorities.

**PR #71 milestone:** 270 tests passed with 70.17% overall line coverage on Python 3.13. Added tests running actual coordinator polling/recovery, Home Assistant sensor properties/device metadata, forecast chart transformations, native forecast history processing, midnight cache invalidation, smoothing, and forecast generation. Home Assistant interfaces and Huawei HTTP calls are mocked; these complement rather than replace live beta validation.\n

**PR #74 milestone:** 278 passing tests, 71.47% line coverage. Production Home Assistant entry lifecycle now has 100% line coverage (setup, session persistence cleanup, initial failure handling, options reload, unload success/failure). No runtime changes.\n

**PR #75 milestone:** 299 tests passing with 76.95% integration line coverage. Real Config Flow functions are exercised with mocked Home Assistant/HTTP boundaries: login errors, CAPTCHA, station selection, session update/reload, reconfiguration guards, and Solcast/native options. Config Flow line coverage reaches 67%. No runtime changes.
