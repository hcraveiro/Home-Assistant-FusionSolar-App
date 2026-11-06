# Invalid or missing Huawei energy readings

Energy readings mirror the current Huawei response, including downward corrections
(for example 35 → 34 kWh). There is no smoothing, offset, monotonic clamp or
invented reset. Numeric zero and numeric strings representing zero are valid.
Malformed numbers, missing/null values, booleans and non-finite numbers remain
unavailable. Failed HTTP daily slots are unavailable and are never skipped.

## Periodic counters: explicit b17 override

For **Today, Week, Month and Year energy counters only**, the exact literal Huawei
`"--"` means **zero**. This explicitly supersedes the earlier b14/b16 placeholder
policy for these four periodic scopes, following the user's requirement. It applies
to scalar period totals, today's monthly-array samples, the current month's house
load sample from the year array, daily grid summaries and supported periodic sums.
It applies to conventional and verified iSitePower-M reader fields without adding
new source mappings or extrapolating unsupported iSitePower readings.

A nonempty periodic vector containing only `"--"` is zero **only when all required
elapsed slots exist**. Mixed `"--"` and valid numeric segments retain the same sum.
A vector containing any other invalid value (including `None`, garbage, `" -- "`,
booleans or NaN) is unavailable, even if other slots are `"--"`. Absent/empty lists,
short elapsed arrays, missing keys and failed responses are not evidence of zero.
Month vectors still include only day 1 through today, and year vectors January
through the current month. Known future slots are excluded as before. A short
weekly response cannot establish a weekly total or turn its last `"--"` into a
Today zero; independently measured daily numbers retain their previous behavior.
Request order, daily spacing and calendar slicing are unchanged.

The exception is **not in the generic numeric or optional energy parsers**.
`_period_grid_energy` and period-aware aggregation apply it at energy-reader
boundaries. `_energy_sum` without a period keeps its earlier skip-only semantics.

The per-device exception uses the explicit kWh allowlist in
`api.models.PERIODIC_ENERGY_COUNTER_KEYS`: the seven established installation
energy families × Today/Week/Month/Year, plus Battery Energy Charged Today,
Battery Energy Discharged Today and Optimizer Energy Today. Names merely ending
in Today/Year are not sufficient. Ratios, statuses, power, social metrics,
capacities, total counters and forced-operation energy setpoints are excluded.
Zero ratio denominators still produce unavailable ratios, not fabricated percentages.
Whitespace variants of `"--"` remain malformed; there is no observed requirement
to normalize them into periodic zero.

## Lifetime: b14/b16 policy retained

Direct lifetime `"--"` remains unavailable. Lifetime vectors discard only literal
`"--"` segments, wherever they occur, and sum every remaining valid number as
supplied, including anomalously large Huawei readings. These sums may represent
partial history: skipped lifetime segments are **not** claimed to be zero.
Empty/all-placeholder lifetime vectors remain unavailable. Any other invalid
value invalidates the whole vector. Lifetime is never sliced using a guessed
start year. No anomaly correction, clamp or numeric sentinel rejection is applied.
Numeric zero and downward lifetime corrections remain valid.

## Scope and compatibility

There are **no state class changes**: every entity retains its existing committed
classification, including `total_increasing` where already used. Entity IDs,
unique IDs, units and device associations are unchanged. Direct scalar totals
retain their source and are not recomputed from arrays (apart from established
source-specific selections such as the current month's house load sample).

Existing Recorder statistics are not rewritten, deleted or repaired. This does
not promise a statistics migration or correct previously accumulated history.
The b11/b14/b16 release policies are historical context; the periodic exception
above is the explicit b17 override, not a reinterpretation of lifetime data.
