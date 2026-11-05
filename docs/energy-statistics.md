# Invalid or missing Huawei energy readings

Energy readings mirror the current Huawei response, including downward corrections
(for example 35 → 34 kWh). There is no smoothing, offset, monotonic clamp or
invented reset. Numeric zero and numeric strings representing zero are real
readings. Missing values, placeholders, malformed numbers, booleans and non-finite
numbers are unavailable, not zero for individual readings. Aggregated vectors
skip only literal Huawei `--` segments and sum the available valid readings.
These sums may represent partial history: excluded segments are not interpreted
as zero, and the result is not a claim of a complete measured total.
Month vectors include only day 1 through today; year vectors include only January
through the current month. Known future calendar slots are excluded, even when
Huawei fills them with placeholders. Absent or short elapsed slots still make the
total unavailable; explicit `--` slots are skipped. Lifetime vectors are never
sliced using a guessed start year. Battery week/month/year/lifetime vectors,
conventional production/self-consumption/load weekly vectors and daily-sourced
weekly totals (including grid import/export and iSitePower-M) discard only literal
`--` placeholders, wherever they occur, and sum every remaining valid number exactly
as supplied, including anomalously large Huawei readings. No correction, clamp
or numeric sentinel rejection is applied. Empty/all-placeholder vectors remain
unavailable, not zero; any other invalid value (including null or NaN) still
makes the total unavailable. Numeric zero remains a valid reading. Direct Huawei
total fields are unchanged and are not recomputed from arrays. Failed HTTP daily
slots remain unavailable and are not skipped.

## Scope and compatibility

This change addresses invalid or missing energy readings only. There are no state
class changes: every entity retains its existing committed classification,
including `total_increasing` where already used. Entity IDs, unique IDs, units and
device associations are unchanged. Valid readings, including zero and downward
corrections, are passed through unchanged; this does not change how Home Assistant
interprets those readings for statistics.

Existing Recorder statistics are not rewritten, deleted or repaired. This change
does not promise a statistics migration or correct any previously accumulated
historical totals. No automatic statistics migration is performed.

In V1.6.8b11, some readings previously exposed as zero or partial sums now become
unavailable when Huawei does not provide all required measurements.
