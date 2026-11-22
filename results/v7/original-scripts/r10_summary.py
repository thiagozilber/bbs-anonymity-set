import csv, sys
from pathlib import Path
from collections import defaultdict
sys.path.insert(0, "/home/claude/thiagozilber/bbs-anonymity-set/analysis/src")
from bbs_analysis import partition as pa
OUT = Path("/home/claude/runs/r10"); runs = sorted(p.name[1:] for p in OUT.glob("a*"))
cols = ["classes", "unique_fraction", "median_set", "mean_set", "mean_log2_set", "degree"]
vals = defaultdict(lambda: defaultdict(list))
for r in runs:
    for row in csv.DictReader((OUT / f"a{r}" / "summary.csv").open()):
        if row["n"] != "200": continue
        for c in cols: vals[(row["tuple"], row["non_answers"])][c].append(float(row[c]))
# Same-partition check, including a tuple with no key-dependent value.
extra = {"key_independent": ("u", "total_statements", "disclosed", "issuer", "verification_method")}
cfg = pa.load_config(Path("/home/claude/thiagozilber/bbs-anonymity-set/configs/analysis/default.toml"))
tuples = {**cfg.tuples, **extra}
obs = {r: pa.read_observations(OUT / f"o{r}.jsonl") for r in runs}
for name, fields in tuples.items():
    for mode in pa.NON_ANSWER_MODES:
        parts = []
        for r in runs:
            p = pa.partition(obs[r], fields, mode)
            parts.append(frozenset(frozenset(v) for v in p.class_provers.values()))
            if name in extra:
                m = pa.metrics(p, 200)
                for c in cols: vals[(name, mode)][c].append(float(m.degree if c == "degree" else getattr(m, c)))
        vals[(name, mode)]["identical"] = len(set(parts)) == 1
w = csv.writer(sys.stdout)
w.writerow(["tuple", "non_answers", "identical_partition"] + [f"{c}_{s}" for c in cols for s in ("min", "max")])
for (t, m), d in vals.items():
    w.writerow([t, m, d["identical"]] + [f"{x:.4g}" for c in cols for x in (min(d[c]), max(d[c]))])
