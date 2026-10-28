"""Partition analysis for one Verifier (RP-U).

Reads the observer's output and, for each configured tuple, groups records
with identical tuples into classes. A record's anonymity set is the number of
distinct Provers in its class: the Provers the Verifier cannot tell apart
from that observation alone.

Curves over N use prefixes of one observation file: the point for N uses the
records of the first N Provers, in the order they appear. This is valid
because populations are prefix-consistent and nothing in the harness depends
on the population size.

Non-answers are handled two ways, reported side by side:
- "class": all non-answers form one extra class;
- "excluded": non-answers are dropped and only answering Provers are
  partitioned.

Only `observation` is used to form tuples. `truth.prover_id` is used to count
Provers and score, never to group.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

# Fields of `observation` in the observer's output (packages/common/src/types.ts).
OBSERVATION_FIELDS = frozenset({
    "u", "l", "disclosed_count", "mandatory_count", "total_statements",
    "selective_indexes", "mandatory_indexes", "header", "label_map",
    "revealed_nquads", "presentation_header", "proof_length", "issuer",
    "verification_method", "disclosed",
})

NON_ANSWER_MODES = ("class", "excluded")

# Tuple key for every non-answer in "class" mode. Cannot collide with a JSON
# array, which is what answered tuples serialize to.
NON_ANSWER_KEY = "no-presentation"


# ---------------------------------------------------------------------------
# Config and input
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnalysisConfig:
    n: tuple[int, ...]
    tuples: dict[str, tuple[str, ...]]


def load_config(path: Path) -> AnalysisConfig:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ValueError(f"{path}: {e}") from e
    try:
        return parse_config(raw)
    except ValueError as e:
        raise ValueError(f"{path}: {e}") from e


def parse_config(raw: dict[str, Any]) -> AnalysisConfig:
    unknown = sorted(set(raw) - {"n", "tuples"})
    if unknown:
        raise ValueError(f"unknown key {unknown[0]!r}")
    n = raw.get("n", [])
    if not isinstance(n, list) or not all(isinstance(x, int) and not isinstance(x, bool) and x >= 1 for x in n):
        raise ValueError("n must be an array of positive integers")
    tuples_raw = raw.get("tuples")
    if not isinstance(tuples_raw, dict) or not tuples_raw:
        raise ValueError("tuples must be a non-empty table of [tuples.<name>] tables")
    tuples: dict[str, tuple[str, ...]] = {}
    for name, t in tuples_raw.items():
        if not isinstance(t, dict) or set(t) != {"fields"}:
            raise ValueError(f"tuples.{name} must have exactly one key, fields")
        fields = t["fields"]
        if not isinstance(fields, list) or not fields or not all(isinstance(f, str) for f in fields):
            raise ValueError(f"tuples.{name}.fields must be a non-empty array of field names")
        bad = [f for f in fields if f not in OBSERVATION_FIELDS]
        if bad:
            raise ValueError(f"tuples.{name}: unknown observation field {bad[0]!r}")
        if len(set(fields)) != len(fields):
            raise ValueError(f"tuples.{name}: a field is listed twice")
        tuples[name] = tuple(fields)
    return AnalysisConfig(n=tuple(sorted(set(n))), tuples=tuples)


def read_observations(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}: line {i}: {e}") from e
            if not isinstance(r, dict) or "truth" not in r or "observation" not in r:
                raise ValueError(f"{path}: line {i}: not an observation record")
            records.append(r)
    verifiers = {r.get("verifier_id") for r in records}
    if len(verifiers) > 1:
        raise ValueError(f"{path}: records from more than one Verifier ({sorted(map(str, verifiers))}); "
                         "this analysis is for a single Verifier")
    return records


def prover_order(records: Iterable[dict[str, Any]]) -> list[str]:
    """Prover ids in order of first appearance."""
    seen: dict[str, None] = {}
    for r in records:
        seen.setdefault(r["truth"]["prover_id"], None)
    return list(seen)


# ---------------------------------------------------------------------------
# Partition and metrics
# ---------------------------------------------------------------------------


def tuple_key(record: dict[str, Any], fields: tuple[str, ...]) -> str:
    """The class key of a record. Non-answers all get the same key."""
    o = record["observation"]
    if o is None:
        return NON_ANSWER_KEY
    missing = [f for f in fields if f not in o]
    if missing:
        raise ValueError(f"observation has no field {missing[0]!r}")
    return json.dumps([o[f] for f in fields], sort_keys=True, ensure_ascii=False, separators=(",", ":"))


@dataclass
class Partition:
    """Records grouped by tuple key, with the distinct Provers per class."""

    keys: list[str]                  # per record, in input order
    provers: list[str]               # per record
    class_provers: dict[str, set[str]]

    def anonymity_sets(self) -> list[int]:
        """Per record: the number of distinct Provers in its class."""
        return [len(self.class_provers[k]) for k in self.keys]


def partition(records: list[dict[str, Any]], fields: tuple[str, ...], non_answers: str) -> Partition:
    if non_answers not in NON_ANSWER_MODES:
        raise ValueError(f"non_answers must be one of {NON_ANSWER_MODES}")
    keys, provers = [], []
    class_provers: dict[str, set[str]] = defaultdict(set)
    for r in records:
        if r["observation"] is None and non_answers == "excluded":
            continue
        k = tuple_key(r, fields)
        p = r["truth"]["prover_id"]
        keys.append(k)
        provers.append(p)
        class_provers[k].add(p)
    return Partition(keys, provers, dict(class_provers))


@dataclass(frozen=True)
class Metrics:
    n: int                    # Provers in the prefix (answering or not)
    provers: int              # Provers in the partition
    records: int              # records in the partition
    classes: int
    unique_fraction: float    # records whose anonymity set is 1
    min_set: int
    median_set: float
    mean_set: float
    max_set: int
    mean_log2_set: float      # expected entropy in bits (log2 of the anonymity set)
    degree: float | None      # mean_log2_set / log2(provers); None when provers < 2


def metrics(part: Partition, n: int) -> Metrics:
    sets = part.anonymity_sets()
    provers = len(set(part.provers))
    if not sets:
        return Metrics(n, 0, 0, 0, 0.0, 0, 0.0, 0.0, 0, 0.0, None)
    mean_log2 = statistics.fmean(math.log2(s) for s in sets)
    return Metrics(
        n=n,
        provers=provers,
        records=len(sets),
        classes=len(part.class_provers),
        unique_fraction=sum(s == 1 for s in sets) / len(sets),
        min_set=min(sets),
        median_set=float(statistics.median(sets)),
        mean_set=statistics.fmean(sets),
        max_set=max(sets),
        mean_log2_set=mean_log2,
        degree=mean_log2 / math.log2(provers) if provers > 1 else None,
    )


def prefix(records: list[dict[str, Any]], order: list[str], n: int) -> list[dict[str, Any]]:
    """Records of the first n Provers in `order`."""
    keep = set(order[:n])
    return [r for r in records if r["truth"]["prover_id"] in keep]


def n_points(config_n: tuple[int, ...], available: int) -> list[int]:
    points = [n for n in config_n if n < available]
    return points + [available]


@dataclass
class Result:
    tuple_name: str
    non_answers: str
    metrics: Metrics
    class_sizes: Counter          # distinct Provers per class -> number of classes
    per_prover: dict[str, int]    # prover -> largest anonymity set among its records


def analyse(records: list[dict[str, Any]], config: AnalysisConfig) -> list[Result]:
    order = prover_order(records)
    results = []
    for n in n_points(config.n, len(order)):
        sub = prefix(records, order, n)
        for name, fields in config.tuples.items():
            for mode in NON_ANSWER_MODES:
                part = partition(sub, fields, mode)
                sets = part.anonymity_sets()
                per_prover: dict[str, int] = {}
                for p, s in zip(part.provers, sets):
                    per_prover[p] = max(per_prover.get(p, 0), s)
                results.append(Result(
                    tuple_name=name,
                    non_answers=mode,
                    metrics=metrics(part, n),
                    class_sizes=Counter(len(v) for v in part.class_provers.values()),
                    per_prover=per_prover,
                ))
    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

SUMMARY_COLUMNS = [
    "tuple", "non_answers", "n", "provers", "records", "classes", "unique_fraction",
    "min_set", "median_set", "mean_set", "max_set", "mean_log2_set", "degree",
]


def write_outputs(results: list[Result], out_dir: Path, per_prover: bool) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []

    path = out_dir / "summary.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(SUMMARY_COLUMNS)
        for r in results:
            m = r.metrics
            w.writerow([r.tuple_name, r.non_answers, m.n, m.provers, m.records, m.classes,
                        _fmt(m.unique_fraction), m.min_set, _fmt(m.median_set), _fmt(m.mean_set),
                        m.max_set, _fmt(m.mean_log2_set), "" if m.degree is None else _fmt(m.degree)])
    written.append(path)

    path = out_dir / "class_sizes.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tuple", "non_answers", "n", "class_size", "classes"])
        for r in results:
            for size, count in sorted(r.class_sizes.items()):
                w.writerow([r.tuple_name, r.non_answers, r.metrics.n, size, count])
    written.append(path)

    if per_prover:
        path = out_dir / "per_prover.csv"
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["tuple", "non_answers", "n", "prover_id", "anonymity_set"])
            for r in results:
                for p, s in r.per_prover.items():
                    w.writerow([r.tuple_name, r.non_answers, r.metrics.n, p, s])
        written.append(path)
    return written


def _fmt(x: float) -> str:
    return f"{x:.6g}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="partition",
        description="Partition one Verifier's observations by tuple and report anonymity-set metrics over N.",
    )
    parser.add_argument("--observations", required=True, type=Path, help="output of verifier observe")
    parser.add_argument("--config", required=True, type=Path, help="analysis config (TOML)")
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--per-prover", action="store_true",
                        help="also write each Prover's anonymity set at each N (large)")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        records = read_observations(args.observations)
        if not records:
            raise ValueError(f"{args.observations}: no observations")
        results = analyse(records, config)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    written = write_outputs(results, args.out_dir, args.per_prover)
    meta = {
        "observations": str(args.observations),
        "observations_sha256": hashlib.sha256(args.observations.read_bytes()).hexdigest(),
        "config": str(args.config),
        "config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
        "verifier_id": records[0].get("verifier_id"),
        "tuples": {k: list(v) for k, v in config.tuples.items()},
    }
    (args.out_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    n_max = max(r.metrics.n for r in results)
    print(f"analysed {len(records)} observations of {n_max} Provers; wrote "
          + ", ".join(str(p) for p in written), file=sys.stderr)
    print(f"  at N = {n_max}:", file=sys.stderr)
    print(f"    {'tuple':<14}{'non-answers':<12}{'classes':>8}{'unique':>9}{'median':>8}{'mean':>9}{'degree':>8}",
          file=sys.stderr)
    for r in results:
        m = r.metrics
        if m.n != n_max:
            continue
        degree = "-" if m.degree is None else f"{m.degree:.3f}"
        print(f"    {r.tuple_name:<14}{r.non_answers:<12}{m.classes:>8}{m.unique_fraction:>9.3f}"
              f"{m.median_set:>8.1f}{m.mean_set:>9.1f}{degree:>8}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
