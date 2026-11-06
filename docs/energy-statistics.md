# Invalid or missing Huawei energy readings (1.6.8b19)

Individual scalar totals and current-day/month samples of literal `--` are
unavailable, including battery daily counters and optimizer daily energy.
No raw marker is converted to zero. Genuine numeric zero remains valid.

All calculated energy accumulations use one policy, without a period exception:
`[2, 3, "--", 4]` sums to **9**. Skip only the exact literal marker. Empty or
all-marker vectors are unavailable. Missing/None, booleans, non-finite readings,
garbage and whitespace variants such as `" -- "` invalidate the whole sum.
Mixed marker/zero vectors can legitimately sum to zero. Skipped markers are
not claimed to be measured zeros; these may be partial aggregates.

Required elapsed vectors must still be complete. Month vectors retain day 1
through today, year vectors January through the current month; known future
slots are excluded. Lifetime has no guessed start-year slicing. Request order,
calendar indexing, endpoint mappings and daily request pacing are unchanged.
Direct totals are not speculatively rebuilt from unrelated arrays.

The mistaken b17/b18 individual/periodic marker-zero exception has been removed.
Shared strict numeric parsing and Wh/kWh conversion are retained. Ratios with
zero denominators remain unavailable. Huawei negative/downward corrections and
large anomalies are not suppressed, clamped, offset or repaired.

Entity IDs, unique IDs, units and every existing state class (including
`total_increasing`) remain unchanged. No Recorder history is modified.
`35 -> --/unavailable -> 35` now preserves the Recorder sum in the isolated
regression. This does **not** fix all statistics risks: real zero/calendar resets
still start new cycles, large downward corrections may be interpreted as resets,
and skipping a marker inside a partial aggregate may lower it enough to cross
that threshold. See [actual Recorder evidence](recorder-validation.md), including
the explicitly historical b18 marker-zero overcount example.
