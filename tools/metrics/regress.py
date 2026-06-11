#!/usr/bin/env python3
"""Finding-regression harness for zbc (issue #19).

Runs `zbc --format=sarif` over a corpus, canonicalizes the findings, and
diffs them against a committed baseline so any rule/engine change shows
its delta:

    added findings   -> a new fire (a genuine catch, OR a false-positive
                        regression — inspect)
    removed findings -> a lost fire (a fixed false positive, OR a recall
                        regression — inspect)

Scope: this is REGRESSION detection on a stable corpus, not labeled
precision/recall. The default corpus is `test/fixtures/` (designed
fire-cases). True precision/recall needs a *labeled* corpus of real code
(the bun/ghostty PRs the fixtures are mined from) — a follow-up; see
the README.

Usage:
    regress.py [--corpus DIR] [--zbc PATH] [--baseline FILE]
    regress.py --update           # (re)write the baseline from the corpus

Exit code: 0 if findings match the baseline, 1 if they differ (CI gate),
2 on a harness error.
"""
import argparse
import json
import os
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))


def run_zbc(zbc, corpus):
    """Return the parsed SARIF document for `corpus`."""
    # zbc prints to stderr (std.debug.print); merge streams.
    r = subprocess.run([zbc, "--format=sarif", corpus],
                       capture_output=True, text=True, cwd=REPO)
    blob = (r.stdout + r.stderr)
    i = blob.find("{")
    if i < 0:
        sys.exit(f"regress: no SARIF from zbc:\n{blob[:500]}")
    try:
        return json.loads(blob[i:])
    except json.JSONDecodeError as e:
        sys.exit(f"regress: malformed SARIF: {e}")


def findings(sarif):
    """Canonical, order-independent finding set + per-rule counts."""
    keys = set()
    for res in sarif["runs"][0]["results"]:
        loc = res["locations"][0]["physicalLocation"]
        region = loc["region"]
        keys.add("\t".join([
            res["ruleId"],
            loc["artifactLocation"]["uri"],
            str(region.get("startLine", 0)),
            str(region.get("startColumn", 0)),
        ]))
    counts = Counter(k.split("\t", 1)[0] for k in keys)
    return keys, counts


def fmt_key(k):
    rule, uri, line, col = k.split("\t")
    return f"{uri}:{line}:{col}  {rule}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="test/fixtures")
    ap.add_argument("--zbc", default=os.path.join(REPO, "zig-out", "bin", "zbc"))
    ap.add_argument("--baseline", default=os.path.join(HERE, "baseline.json"))
    ap.add_argument("--update", action="store_true", help="write the baseline")
    args = ap.parse_args()

    if not os.path.exists(args.zbc):
        sys.exit(f"regress: zbc not built at {args.zbc} (run `zig build`)")

    keys, counts = findings(run_zbc(args.zbc, args.corpus))

    if args.update:
        with open(args.baseline, "w") as f:
            json.dump({
                "corpus": args.corpus,
                "total": len(keys),
                "per_rule": dict(sorted(counts.items())),
                "findings": sorted(keys),
            }, f, indent=2)
            f.write("\n")
        print(f"baseline written: {len(keys)} findings across "
              f"{len(counts)} rules over {args.corpus}")
        return

    if not os.path.exists(args.baseline):
        sys.exit(f"regress: no baseline at {args.baseline} (run --update first)")
    with open(args.baseline) as f:
        base = json.load(f)
    base_keys = set(base["findings"])

    added = sorted(keys - base_keys)
    removed = sorted(base_keys - keys)

    print(f"corpus {args.corpus}: {len(keys)} findings "
          f"(baseline {base['total']})")
    if not added and not removed:
        print("✓ no change vs baseline")
        return

    if added:
        print(f"\n+ {len(added)} NEW finding(s) — new catch OR false-positive regression:")
        for k in added:
            print(f"    + {fmt_key(k)}")
    if removed:
        print(f"\n- {len(removed)} REMOVED finding(s) — fixed FP OR recall regression:")
        for k in removed:
            print(f"    - {fmt_key(k)}")

    # per-rule count deltas
    base_counts = Counter(base["per_rule"])
    deltas = {r: counts.get(r, 0) - base_counts.get(r, 0)
              for r in set(counts) | set(base_counts)}
    deltas = {r: d for r, d in deltas.items() if d}
    if deltas:
        print("\nper-rule deltas:")
        for r, d in sorted(deltas.items()):
            print(f"    {d:+d}  {r}")
    sys.exit(1)


if __name__ == "__main__":
    main()
