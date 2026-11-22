"""Summarize the repeated runs of V7: min and max of each metric over the runs,
per tuple and treatment of non-answers, at the largest N, and whether every run
gives the same partition. Adds the key-independent tuple (values the HMAC keys
do not affect), which is not in the default analysis config.

Usage: python3 scripts/v7_summary.py RUN_DIR > RUN_DIR/v7_summary.csv

RUN_DIR holds oNN.jsonl and aNN/summary.csv from scripts/v7_runs.sh. The thesis
table (results/v7/v7_summary.csv) was made with
results/v7/original-scripts/r10_summary.py, which differs only in its paths and
in fixing N = 200.
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "analysis" / "src"))
from bbs_analysis import partition as pa  # noqa: E402

KEY_INDEPENDENT = ("u", "total_statements", "disclosed", "issuer", "verification_method")
COLS = ["classes", "unique_fraction", "median_set", "mean_set", "mean_log2_set", "degree"]


def main(run_dir: Path) -> None:
    runs = sorted(p.name[1:] for p in run_dir.glob("a*") if p.is_dir())
    if not runs:
        sys.exit(f"no aNN/ directories in {run_dir}")
    rows = [list(csv.DictReader((run_dir / f"a{r}" / "summary.csv").open())) for r in runs]
    n = max(int(row["n"]) for row in rows[0])

    vals = defaultdict(lambda: defaultdict(list))
    for run_rows in rows:
        for row in run_rows:
            if int(row["n"]) != n:
                continue
            for c in COLS:
                vals[(row["tuple"], row["non_answers"])][c].append(float(row[c]))

    cfg = pa.load_config(REPO / "configs" / "analysis" / "default.toml")
    tuples = {**cfg.tuples, "key_independent": KEY_INDEPENDENT}
    obs = {r: pa.read_observations(run_dir / f"o{r}.jsonl") for r in runs}
    identical = {}
    for name, fields in tuples.items():
        for mode in pa.NON_ANSWER_MODES:
            parts = []
            for r in runs:
                p = pa.partition(obs[r], fields, mode)
                parts.append(frozenset(frozenset(v) for v in p.class_provers.values()))
                if name == "key_independent":
                    m = pa.metrics(p, n)
                    for c in COLS:
                        vals[(name, mode)][c].append(float(getattr(m, c)))
            identical[(name, mode)] = len(set(parts)) == 1

    w = csv.writer(sys.stdout)
    w.writerow(["tuple", "non_answers", "identical_partition"]
               + [f"{c}_{s}" for c in COLS for s in ("min", "max")])
    for (t, mode), d in vals.items():
        w.writerow([t, mode, identical[(t, mode)]]
                   + [f"{x:.4g}" for c in COLS for x in (min(d[c]), max(d[c]))])


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]))
