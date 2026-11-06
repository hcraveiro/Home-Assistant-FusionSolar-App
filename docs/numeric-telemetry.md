# Numeric telemetry contract (proposed 1.6.8b17)

Malformed telemetry is **unavailable**, not measured zero. The only explicit
placeholder exception is the exact literal `--` on classified Today/Week/Month/Year
**energy counters**, documented below. This does not repair Recorder history or
change sensor IDs, units, device classes or state classes.

## Shared parser

`utils.extract_numeric(value, unit="", *, default_unit=None) -> float | None`

- Accept JSON integers/floats and complete numeric strings, including signs,
  decimal precision and finite scientific notation. Whitespace around a value or
  between its number and unit is allowed; attached units are allowed too.
- Reject booleans **before** numeric conversion, missing values, placeholders,
  nonnumeric text, containers/other objects, NaN, infinities and overflow.
- No default zero, clamping, absolute-value conversion, correction suppression or
  rounding. Real zero and negative/corrected readings remain valid. Readers keep
  their existing rounding and domain-specific discovery rules.
- `unit` specifies the output dimension. An empty unit means dimensionless/count,
  not permission to remove an arbitrary suffix.
- Bare numbers/strings use `default_unit`, or `unit` if no default is supplied.
  An **explicit** suffix overrides the default, but must match the dimension.
- Only scale conversions are **W → kW** and **Wh → kWh**. These suffixes are
  case-insensitive, preserving the earlier flow/energy convention. Other accepted
  suffixes are `%`, `V`, `A`, `Hz`, `°C`, `MΩ`, `var`, `kg`, `min` (matching case).
  `C` is also accepted as Celsius because the existing battery module replay
  contains `24.5 C`. No guessed aliases, grouping separators, trailing prose,
  wrong-dimension suffixes or unsupported SI prefixes are accepted.

Examples:

```python
extract_numeric("600W", "kW")                         # 0.6
extract_numeric(600, "kW", default_unit="W")           # 0.6
extract_numeric("0.6 kW", "kW", default_unit="W")     # 0.6, not 0.0006
extract_numeric("70.8 %", "%")                        # 70.8
extract_numeric("70 W", "%")                         # None
extract_numeric(False, "kW")                         # None
extract_numeric(" -- ", "V")                         # None
extract_numeric("0", "V")                            # 0.0
```

`api.models.NUMERIC_DEVICE_UNITS` supplies the dimensions for the dynamic factory
and installation value getter without importing the HA sensor platform. The
actual-HA numeric checker asserts that it agrees with `FusionSolarSensor.UNIT_MAP`.

## Reader policies deliberately retained

- Flow/dynamic power defaults to **kW**. Flow SOC is a separate `%` reading and
  cannot accept power units. Grid direction requires complete valid inputs and a
  finite calculated balance.
- Meter watt signals `10004`, `10019`, `10020`, `10021` default to **W**, normalized
  once to kW. Malformed active power cannot report `idle`; only measured zero can.
- Battery configuration maximum charge/discharge signals also default to W;
  explicit kW is not scaled a second time. Existing configuration nonnegative
  and SOC-range policies are unchanged.
- Each derived PV power needs valid finite V **and** A, plus a finite product.
  The MPPT total requires all visible/previously confirmed pairs, not a partial
  sum. Incomplete calculations do not overwrite independently measured PV power.
  Invalid/missing input is not a zero-only discovery placeholder.
- Battery SOH retains the established **strictly positive** discovery policy;
  this change does not declare previously suppressed SOH sentinel values valid.
  A missing/invalid pack quantity still falls back to zero **for topology control
  only**, preserving discovery from explicit pack keys.
- Dynamic percentages still round; installation percentages still truncate.
  Installation counts still round. Existing numeric precision/rounding is retained.
- Social metrics are independent: missing/invalid values (including an unavailable
  entire optional response) stay unavailable, while other valid metrics survive.
- The generic energy parser keeps its strict grammar, explicit Wh conversion and
  unavailable `--`. **New user-required b17 exception:** energy-reader boundaries
  interpret exact literal `--` as zero for Today/Week/Month/Year only. Nonempty
  all-`--` elapsed vectors also become zero when complete; missing/short/failed
  data and any other invalid value remain unavailable. Whitespace variants do not
  qualify. Lifetime keeps b14/b16's skip-only vector policy: mixed `--`+valid sums
  survive, all-`--`/empty vectors and direct `--` stay unavailable. Huawei lifetime
  anomalies and corrections remain untouched.
- Per-device periodic kWh counters use an explicit known-counter allowlist in
  `api.models`, shared by the factory/getter and optimizer reader. It includes
  Battery Energy Charged/Discharged Today and Optimizer Energy Today, but not
  arbitrary names, total/lifetime counters, capacity, forced-operation setpoints,
  statuses, power, ratios or social metrics. Zero ratio denominators stay unknown.
  See [energy statistics policy](energy-statistics.md) for the precise b17 override.

## Regression checks

`tests/test_numeric_telemetry.py` and `tests/test_periodic_energy_placeholders.py`
exercise the real shared parser, assembled API factory/getter and production
readers with synthetic invalid, zero, negative, unit-conversion, periodic literal
placeholder, unchanged lifetime and incomplete-calculation cases. The older issue #51
visibility tests now use the real parser rather than a false-zero fake.

`tests/api_profiles/check_numeric_homeassistant.py` is a **standalone actual-HA**
checker, not a pytest/AST substitute. It derives a temporary four-frame synthetic
profile from existing PV/meter HTTP routes and registers real HA entities:

**valid → malformed/unavailable → legitimate zero/idle → recovery**.

It checks source HTTP polling, isolation of unrelated valid values, stable
registered entity/unique/device IDs, units/classes, and no network attempts.
Energy transitions also prove registered periodic `--` → **0 kWh**, malformed →
**unavailable**, lifetime `--` → **unavailable**, mixed lifetime vectors retaining
valid segments, and corrected lifetime recovery without clamping. It
uses `OfflineSession` with no network adapters plus DNS/TCP/Requests guards.
Only temporary container files are written; no eighth persistent profile is
added. Run using the same read-only, network-disabled image invocation described
in `docs/mock-scenarios.md`, substituting this checker path.

These are **synthetic regressions, not new Huawei captures or hardware evidence**.
They supplement the existing seven-profile lifecycle, coexistence and actual-HA
class checkers; they do not claim Recorder/statistics validation or live-account
coverage. Release validation must also run the full pytest suite with branch
coverage under native Requests/simplejson and the controlled stdlib alternative.
