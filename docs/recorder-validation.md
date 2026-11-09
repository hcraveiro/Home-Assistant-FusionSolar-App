# Disposable Recorder validation

This check characterizes the **unchanged** `SensorStateClass.TOTAL_INCREASING`
energy classifications using Home Assistant **2026.10.4**, its real Recorder and
an isolated SQLite database. It is not a migration, a sensor-class change, a
history repair, or evidence that arbitrary Huawei historical corrections have
correct statistical meaning.

## Reproduce safely

Use the existing image; do not pull, mount a live HA config, enable networking,
or run this checker inside development/production HA:

```sh
docker run --rm --pull never --network none --read-only --tmpfs /tmp \
  -v "$PWD:/src:ro" -w /src \
  -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
  --entrypoint python ghcr.io/home-assistant/home-assistant:2026.10.4 \
  tests/api_profiles/check_recorder_homeassistant.py \
  > recorder.json 2> recorder.stderr
```

Run from a checkout containing the checker. The image must already contain its
normal Recorder dependencies. No pytest, dependency downloads, HTTP server,
`default_config`, live HA endpoint, credentials or production database is used.
Only the JSON report and diagnostics are written to the host by the shell.
All HA configuration, supported registry/Store writes, generated profile and
SQLite files are in the container's temporary `/tmp` and destroyed after the run.

DNS, IPv4/IPv6 TCP connections and Requests transport calls are denied and
counted, even when a production reader catches an exception. Docker separately
disables networking. Every profile identity starts `MOCK_RUNTIME_`, entry host
is `example.invalid`, credentials are fictional, and the offline session has no
Requests adapters. The checker asserts zero network attempts and unmatched
mock requests.

## What is exercised

- A temporary derivative of `transitions-energy`, containing synthetic HTTP
  snapshots rather than injected HA states or constructed `Device` objects.
- Actual integration config flow, config entry setup, production
  `FusionSolarAPI.get_devices`, readers, coordinator and sensor platform.
- Actual entity/device registries and unchanged kWh / energy /
  `total_increasing` classifications for Panel Production Today, Week, Month,
  Year and Lifetime. Identity stability is checked throughout the input sequence.
- HA's `async_initialize_recorder` bootstrap helper and normal
  `async_setup_component(..., "recorder", ...)`, temporary file SQLite,
  real recorded state-change events, and the actual sensor Recorder platform.
- `StatisticsTask` → Recorder `compile_statistics` → sensor compilation,
  short-term statistics and the hourly long-term roll-up at `:55`.
- `statistics_during_period` for both `5minute` and `hour`, plus Recorder's
  history API. Expected state/sum values are asserted, not inserted.

Wall-clock sources (`time.time`, HA entity helper's imported wall-time alias,
HA UTC/local helpers, Recorder's statistics creation-time alias and integration
reader `datetime` references) are controlled. Asyncio/thread monotonic time, actual
Recorder threading, database operations, production request pacing, state
creation, compilation and statistical calculations are **not** substituted.
Each interval's state events are committed before the real compilation task is
queued. HA clock timers are not dispatched: input polls and compilation
intervals are explicitly driven, without waiting real five-minute/hour periods.
The JSON preserves state/history timestamps and actual compiled rows.

## Corrected b19 contract: actual isolated Recorder result

The updated checker passes with the same real SQLite/Recorder pipeline and all
classes unchanged. Scalar `35 -> "--"/unavailable -> 35` retains sum **5 -> 5**;
there is no fabricated zero and no +35 overcount at recovery. All five targets
have 33 short-term rows and three hourly rows. Current hourly sums are:

| Hour UTC | Today / Month / Year | Week | Lifetime |
|---|---:|---:|---:|
| Dec 31 22:00 | 7 | 28 | 7 |
| Dec 31 23:00 | 75 | 300 | 75 |
| Jan 1 00:00 | 77 | 302 | 77 |

Measured zero, real calendar reset, 1/0.01 kWh corrections and the >10% drop
remain exercised, not hidden. Real zero starts a new cycle. A sufficiently large
downward correction still triggers TOTAL_INCREASING reset detection. Ignoring
markers in a mixed aggregate can lower a partial sum and trigger the same risk;
no claim that all statistical risks are fixed is justified. Production-reader
unit regressions additionally prove mixed `[2,3,"--",4] -> 9` across week/month/
year/lifetime, all-marker unavailable and genuine zero valid. No SQL sum injection,
history repair or live data is used.

Current artifacts: `/tmp/opencode/b19-validation/ha-runtime-results/`.
The following measurements are retained **honestly as historical evidence** of
the old policy, not assertions of current b19 behavior.

## Historical interpretation (old policy)

A numeric entity state and its cumulative Recorder `sum` are different things.
The initial counter value establishes Recorder's zero point; it is not itself
added as new energy. `last_reset: null` does not establish that no inferred reset
occurred: `total_increasing` uses drop detection without publishing an explicit
`last_reset` value.

The check deliberately distinguishes:

- monotonic increments;
- absolute downward corrections of 1 kWh (`35 → 34`) and 0.01 kWh;
- a drop exceeding HA's relative reset threshold;
- a **measured numeric zero**;
- invalid/null/garbage/spaced-marker values, unavailable history and recovery;
- b17's **exact literal** `"--" → 0 kWh` for periodic energy, versus
  `"--" → unavailable` for Lifetime.

The exact literal-marker rule is not extended to other invalid inputs, nor is
Lifetime changed. Neither corrections nor resets are clamped/suppressed.

## Historical b18 validation / OLD b17–b18 policy (not current b19 behavior)

The standalone run **passed** against published V1.6.8b17 (`0540c9c`), with
17 HTTP snapshots, 17 production discovery calls, 290 offline HTTP requests,
92 registered entities, three registered devices and **zero network attempts**.
It compiled 36 five-minute intervals spanning `2026-12-31 22:00 UTC` through
`2027-01-01 01:00 UTC`. Four periodic targets each returned 34 short-term rows;
Lifetime returned 33. All five returned three actual hourly long-term rows.
The missing short-term rows are asserted gaps, not invented zero observations.
Nine separate profile/clock unit tests also passed; those tests alone do **not**
validate Recorder.

The run used the already-present image
`ghcr.io/home-assistant/home-assistant:2026.10.4`, local image ID
`sha256:8e7d93e48bed8980ec6924f8620928efa3bf981e3d33aa3be047944f37c6cd3a`.
Artifacts from this run are in `/tmp/opencode/b18-recorder-results/`:
`commands.sh`, `recorder.json`, `recorder.stderr`, `observed-statistics.csv`,
`profile-junit.xml` and `unit-tests.log`.

### Actual short-term observations

Values below are kWh. Today, Month and Year have identical values in this
synthetic sequence. Week is initially four times these values because four
elapsed daily samples are supplied; it is checked independently. “Δsum” is the
difference between consecutive **returned Recorder sums**, not a hand-derived
replacement for compilation. Floating-point results such as
`3.990000000000002` are displayed rounded; assertions use absolute tolerance
`1e-8`, distinct from HA's **relative reset threshold**.

| UTC interval start | Input / event | Periodic state | Periodic sum | Periodic Δsum | Lifetime state | Lifetime sum |
|---|---|---:|---:|---:|---:|---:|
| Dec 31 22:00 | Baseline 30 | 30 | 0 | 0 | 30 | 0 |
| 22:05 | Increase to 35 | 35 | 5 | +5 | 35 | 5 |
| 22:10 | Correction 35 → 34 | 34 | 4 | −1 | 34 | 4 |
| 22:15 | Correction 34 → 33.99 | 33.99 | 3.99 | −0.01 | 33.99 | 3.99 |
| 22:20 | Recovery to 35 | 35 | 5 | +1.01 | 35 | 5 |
| 22:25 | Null → unavailable | 35* | 5 | 0 | 35* | 5 |
| 22:30, 22:35 | Garbage / spaced `" -- "` | no row | no row | — | no row | no row |
| 22:40 | Exact literal `"--"` | 0 | 5 | 0 | no row | no row |
| 22:45 | Same value 35 returns | 35 | 40 | **+35** | 35 | 5 |
| 22:50 | Measured numeric zero | 0 | 40 | 0 | 0 | 5 |
| 22:55 | Increase to 2 | 2 | 42 | +2 | 2 | 7 |
| 23:00 | Increase to 35 | 35 | 75 | +33 | 35 | 40 |
| 23:05 | Drop 35 → 30 (>10%) | 30 | 105 | **+30** | 30 | 70 |
| 23:10 | Return to 35 | 35 | 110 | +5 | 35 | 75 |
| Jan 1 00:00 | Genuine calendar reset | 0 | 110 | 0 | 35 | 75 |
| 00:05 | New-period energy 2 | 2 | 112 | +2 | 37 | 77 |

\* The entity is actually `unavailable`; the transition interval still contains
its preceding valid recorded state, so the compiled statistic's `state` is 35.
The following entirely unavailable intervals have no valid float history and
produce **no statistic row**. Recovery uses the previous compiled counter
without fabricating zero. The JSON includes both raw entity/history states and
compiled statistics so these cannot be confused.

### Tolerated corrections versus inferred resets

HA 2026.10.4's sensor Recorder detects a reset when
`new_value < 0.9 * previous_value`. Thus the absolute 1 kWh correction
`35 → 34` (about 2.86%) and the 0.01 kWh correction **do not reset**: their
actual sums decrease by 1 and 0.01 respectively. HA emits the expected
“not strictly increasing” warnings; the checker does not suppress those
warnings or clamp the states/sums.

In contrast, `35 → 30` is below 31.5 and **is interpreted as a reset**.
Recorder adds the new-cycle value 30: sum 75 → 105 in the periodic example,
rather than applying a −5 correction. If this input meant a historical
correction rather than a real reset, that interpretation would be wrong by
35 kWh at this point. This run does not establish the meaning of any real
Huawei drop.

### Exact placeholder zero can create double counting

In the historical b18 run, the b17 periodic policy was preserved exactly. Before the placeholder, the
counter is 35 and the actual sum is 5 (initial baseline 30). The periodic
`"--"` is parsed to a numeric zero. Recorder infers a reset but leaves sum at 5.
When **the same** 35 returns, Recorder treats it as new-cycle energy and the
actual sum becomes **40**, an excess of **35 kWh** if the placeholder merely
meant temporarily absent data. The Lifetime control stays unavailable at the
marker and returns to 35 with sum still **5**. Week similarly moves from
sum 20 to 160 when its counter 140 returns: an excess of 140 in that fictional
aggregate.

This is concrete double-counting evidence, not merely a theoretical warning.
A real measured zero also starts a new cycle, but that may be legitimate for
a counter that truly reset. A literal placeholder is not evidence by itself
that a physical/calendar reset occurred.

### Calendar boundary and actual long-term roll-up

At the controlled midnight/new month/new year boundary, actual Today, Month
and Year states reset 35 → 0, preserving sum 110; new energy 2 produces sum
112. A separate retained December HTTP route preserves the weekly elapsed
days: Week stays 140/sum 440 across midnight and then becomes 142/sum 442.
Lifetime stays 35/sum 75 and then increases to 37/sum 77. This exercises
production previous-month reading and calendar indexing without resetting
Lifetime or incorrectly zeroing the ongoing week. A Monday week-boundary
reset and DST transitions were not exercised.

| Hour starting UTC | Today / Month / Year: state, sum | Week: state, sum | Lifetime: state, sum |
|---|---|---|---|
| Dec 31 22:00 | 2, 42 | 8, 168 | 2, 7 |
| Dec 31 23:00 | 35, 110 | 140, 440 | 35, 75 |
| Jan 1 00:00 | 2, 112 | 142, 442 | 37, 77 |

These are returned **hourly long-term statistics**, generated by the real
`:55` roll-up, not raw history labeled as statistics. `last_reset` remains
null throughout, including inferred resets.

For reliable completion the checker queues an unconditional real
`SynchronizeTask` after state writes and compilation. Merely calling
`async_block_till_done()` can return while a task already removed from the
queue is still running; the explicit FIFO/commit barrier avoids inspecting
incomplete results. The checker also verifies entity timestamps belong to the
controlled timeline, rather than silently falling back to current states.

## Limits and decision boundary

These are fictional deterministic samples processed by the real HA engine, not
hardware captures. Their frequency, timing and meaning cannot establish whether
Huawei intended a correction, a true counter reset or temporarily absent data.
A successful characterization must not be described as proof that all historical
corrections are statistically correct. Any subsequent policy or class change,
and especially any repair of existing history/statistics, requires a separate
explicit decision; this check performs none.

**Point 3 outcome:** actual Recorder validation is now reproducible and executed;
the statistical policy has been characterized, **not repaired or declared safe**.
The evidence leaves explicit decisions about the accepted periodic placeholder
zero/recovery effect and genuine downward corrections crossing HA's reset
threshold. No entity class, parsing policy, existing history or statistics was
changed by this work.
