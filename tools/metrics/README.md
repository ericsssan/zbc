# Finding-regression harness (issue #19)

zbc's dominant ongoing cost is false-positive tuning, and until now there
was **no measurement** — every suppression commit was validated by hand.
This harness gives a regression signal: run zbc over a stable corpus,
canonicalize the findings, and diff against a committed baseline.

```
tools/metrics/regress.py            # diff current findings vs baseline
tools/metrics/regress.py --update   # (re)write the baseline
tools/metrics/baseline.json         # committed baseline (49 findings, 32 rules)
```

A finding is keyed by `(rule_id, file, line, col)`, so the diff is
order-independent. Output:

```
+ NEW finding   — a new fire: a genuine catch, OR a false-positive regression
- REMOVED finding — a lost fire: a fixed false positive, OR a recall regression
```

plus per-rule count deltas. Exit code is `0` when findings match the
baseline and `1` when they differ — so it doubles as a CI gate.

## Workflow

After any rule or engine change, run `regress.py`. If the diff is empty,
the change is finding-neutral. If it isn't, **inspect each delta** and
decide whether it's the intended effect (e.g. the value_range min-length
work should *remove* `ptr-slice-without-bounds-check` findings that are
now provably safe). If intended, `--update` to re-baseline; commit the
new `baseline.json` alongside the change so the diff stays meaningful.

## Corpus

Default corpus is **`test/fixtures/`** — the per-rule designed fire-cases
mined from real bun/ghostty/tigerbeetle bugs. Point it elsewhere with
`--corpus DIR` (e.g. a checkout of a real project) for a richer signal.

Note: zbc's own `src/` produces **zero** findings (it's clean), so it is
not a useful corpus here.

## Scope / limitation — this is regression detection, not precision/recall

The harness measures *change* against a baseline; it does not measure
absolute precision/recall, because the corpus is **unlabeled** — a
finding isn't tagged true- vs false-positive. The labeled-corpus piece
(annotating real-code findings as TP/FP so we can report precision and
recall, ideally in SARIF where TP = `result` and FP = a `suppression`
with `state:"accepted"` — see issue #19) is the remaining follow-up.
With labels, the same diff machinery yields precision/recall as a
set-diff of results vs suppressions between the run and the labeled
baseline.
