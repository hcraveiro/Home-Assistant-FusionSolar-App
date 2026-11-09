# Forecast and polling performance validation (b18 audit point 4)

## Scope and policy

This change only optimizes `forecast/native.py`. It does **not** change Huawei
request order, polling interval, daily request spacing, energy parsing, sensor
classes, provider selection, or prediction/smoothing algorithms. No API-period
response cache has been added.

A valid native daily delta profile was already frozen for the local date, source
entity, step size, history-day count, and algorithm version. Previously every
poll nevertheless fetched and indexed the full seven-day history before checking
that profile. The builder now checks the same persisted-cache contract first:

- On a valid profile hit, query **today plus the existing six-hour midnight
  lookback**, not seven previous days plus that lookback.
- Continue querying fresh Recorder actuals on **every** poll. Do not reuse an
  entire forecast or an adaptive current-now result.
- Rebuild from full history after midnight, source/configuration/algorithm
  changes, or an incomplete profile. Debug mode also retains full history so
  historical diagnostics are unchanged.
- If the short query contains no numeric samples, retry full history. This
  preserves the old sparse/empty-history behavior, at the cost of an extra query
  in that uncommon path.
- Index histories of at least 1,000 samples and generate their daily profile in
  the HA executor. Small histories avoid executor scheduling overhead. These
  calculations only read supplied samples/configuration and return local data;
  entity-registry resolution, cache mutation, and Store operations stay on-loop.
- A genuinely absent/not-yet-set-up Recorder returns an unavailable forecast
  (`forecasted_today`/`remaining_today` remain `None`, empty curve), not a zero
  prediction. A missing instance after Recorder setup, a malformed instance, and
  unrelated/query failures are not suppressed. A working Recorder returning an
  empty history retains its previous actual-value fallback.

Provider selection remains in the unchanged coordinator. While Solcast is
selected, the native builder is idle. Returning to native still validates its
original daily profile and refreshes actuals; this patch adds no provider-level
or current-now cache.

## Offline reproduction

Use a disposable HA **2026.10.4** image already present locally. No live config,
credentials, network, dependency installation, or Home Assistant restart is used.
`/tmp/opencode/b15-review-deps` is an existing read-only pytest dependency mount.
Forecast history is entirely synthetic. The existing offline API profile is
marked `origin: synthetic`, with fictional identities and energy readings; its
provenance also notes curated observed-safe configuration/info values. No live
account readings are queried.

```bash
SRC=/tmp/opencode/fusionsolar-performance-b18
OUT=/tmp/opencode/b18-performance-results
mkdir -p "$OUT"
git -C "$SRC" show 0540c9c:custom_components/fusion_solar_app/forecast/native.py > "$OUT/baseline_native.py"
docker run --rm --pull never --network none --read-only --tmpfs /tmp \
  -v "$SRC:/src:ro" -v /tmp/opencode/b15-review-deps:/deps:ro \
  -v "$OUT:/out" -w /src \
  -e PYTHONPATH=/deps:/src -e PYTHONDONTWRITEBYTECODE=1 \
  --entrypoint python ghcr.io/home-assistant/home-assistant:2026.10.4 \
  tests/api_profiles/check_forecast_performance.py \
  --baseline /out/baseline_native.py \
  > "$OUT/forecast-performance.json" 2> "$OUT/forecast-performance.stderr"
docker run --rm --pull never --network none --read-only --tmpfs /tmp \
  -v "$SRC:/src:ro" -v /tmp/opencode/b15-review-deps:/deps:ro \
  -w /src -e PYTHONPATH=/deps:/src -e PYTHONDONTWRITEBYTECODE=1 \
  --entrypoint python ghcr.io/home-assistant/home-assistant:2026.10.4 \
  -m pytest tests/test_native_forecast_behavior.py \
  tests/test_native_forecast_full_behavior.py \
  tests/test_solcast_forecast_behavior.py tests/test_forecast_attribute_budget.py \
  -q --tb=short -p no:cacheprovider
```

The complete local invocation is also saved as
`/tmp/opencode/b18-performance-results/commands.sh`.

## Measurement method

`tests/api_profiles/check_forecast_performance.py` loads **both real builder
implementations** against identical synthetic inputs, not an AST approximation.
It runs in actual HA with real registry resolution and HA executors; the Recorder
query and Store are explicit deterministic seams. The query seam implements
bounds and the preceding start-state behavior. It does **not** time SQLite or a
live Recorder, and its row counts are not production database measurements.

The dense workload has five-second cumulative readings, daily resets, and
non-numeric samples. Five polls include a cold build and four same-day cache
hits, advancing time and current production identically before/after. Assertions
compare the **entire** forecast dataclass (curve, actuals, remaining forecast,
debug, timestamps) and persisted smoothed profile exactly. Query counters/bounds,
rows indexed, execution thread IDs, Store load/save counts, and elapsed times
are recorded. Deterministic row/work reduction and thread placement, not small
wall-clock differences, are the acceptance criteria.

Additional old/new comparisons cover persisted hits, empty/unavailable/sparse
history, fallback to full history, missing current production, midnight,
source/step/history-days/algorithm changes, incomplete profiles, debug output,
and fresh actuals after a provider pause. Cancellation is injected into both new
executor workloads; the worker is released and awaited to prove it cannot
publish or persist a late result. Network/DNS/requests guards retain attempted
violations even if an API reader catches the raised exception.

The polling check invokes the real API readers with the fictional
`single-battery-config-denied` offline backend twice before and twice after the
forecast checks. It compares request order/count traces and every daily-spacing
argument. The social-contribution `clientTime` clock is captured once for both
runs; only the existing portal `_` cache-buster is ignored in trace comparison.
Sleeps are virtualized **in the test only**, not removed from production. The
date-dependent Monday-through-today request count remains intentional.

## Results and limits

Completed in the isolated HA 2026.10.4 container against published b17
`0540c9c` (baseline native file SHA-256
`ba9a2ee5f4c9ed34fe85ee02bf4533b0c332a19600dc4d370474d3b96b2bba1a`):

| Metric, identical dense synthetic workload | Before | After |
| --- | ---: | ---: |
| Recorder-seam queries across five polls | 5 | 5 |
| Full multi-day queries | 5 | 1 |
| Returned/indexed rows across five polls | 669,875 | 186,035 |
| Returned/indexed rows on four profile hits | 535,924 | 52,084 |
| Instrumented material calculations on event-loop thread | 6 | 0 |
| Store loads / saves | 1 / 1 | 1 / 1 |
| Cold build elapsed, supplementary single observation | 273.96 ms | 334.79 ms |
| Median of four hot builds, supplementary | 117.94 ms | 21.17 ms |

Thus row work fell **72.23% overall** and **90.28% on the four cache hits**.
The cold build was slower in this observation; moving work off-loop is not a
claim of reduced cold CPU cost or a production throughput guarantee. All six
material indexing/profile calculations moved to worker threads; actual Recorder
query jobs also remained off-loop. The instrumented before/after forecast output
hashes match exactly:
`f9d47b852a0a5ca4c9ed35ba27ffb3bae85033d00ebe832918cbcb5190e9149f`.
The persisted smoothed-profile hashes also match:
`c821df889dcc7adc732a5330b3479e46de5cce770bfc7c4e5d67d033e1d47435`.

All **16** additional old/new equivalence scenarios passed. Both cancellation
injections finished their worker with **zero late cache writes**. Three absent
Recorder polls produced unavailable forecasts with **zero warnings**; five
unexpected setup/instance/query failures propagated instead of being masked.

For the Friday polling check, fresh offline API instances made **23 then 17**
fictional requests on their first and second polls respectively, both before and
after the forecast checks. Each poll retained **five one-second daily spacing
calls**. The ordered method/path/stable-query/body/spacing trace matched exactly
before/after. First/second request counts differ because existing instance-local
metadata/configuration caching remains intact. This is not a new historical
energy cache. Transport guards recorded **zero network attempts**.

Focused pytest: **40 passed**, with dependency/plugin deprecation warnings only.
The standalone checker passed with empty stderr. See `forecast-performance.json`
for exact bounds/counts, hashes, individual scenarios, cancellation results,
polling traces, and timings; pytest output is in `focused-pytest.log`.

Remaining costs are deliberately retained:

- Actual-curve history still requires one Recorder query per ordinary poll.
- Cold/midnight/config/source-invalidated builds still query the full history
  window and perform the same robust filtering and smoothing.
- Sparse numeric-history fallback may use two queries; avoiding that would change
  existing predictions in edge cases.
- Debug mode still queries/scans full history to preserve its diagnostics.
- **Historical b18 evidence (not current cadence):** the cloud API performed
  serial per-day reads with one-second trailing spacing. In the 1.6.9b2 controlled
  experiment every energy endpoint attempt instead has a minimum two-second
  start-to-start interval per API instance, with no trailing daily pause. Scan
  configuration, request order, and energy semantics remain unchanged. There is
  no historical-period cache and no claim that this resolves HTTP 418.
- Executor jobs cannot be forcibly stopped once running. Their results are local;
  cancellation prevents subsequent cache publication/persistence, but a worker
  can consume CPU until completion. Python's GIL still applies.

This checker is not a full config-entry unload test or a real database throughput
benchmark. It does prove cancellation safety of the added executor boundaries.
Integration lifecycle and full-suite validation are separate checks run by the
parent audit session after merging.
