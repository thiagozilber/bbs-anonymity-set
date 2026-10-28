import csv
import json
import math
import shutil
import subprocess
from pathlib import Path

import pytest

from bbs_analysis import partition as pa
from bbs_analysis import popgen

REPO = Path(__file__).resolve().parents[2]
CORE = ("u", "total_statements", "selective_indexes", "header")


def obs(prover, u=1, header="h1", disclosed=None, index=0, **extra):
    observation = {
        "u": u, "l": u + 1, "disclosed_count": 1, "mandatory_count": 3, "total_statements": u + 4,
        "selective_indexes": [0], "mandatory_indexes": [0, 1, 2], "header": header,
        "label_map": [[0, 0], [1, 1]], "revealed_nquads": [], "presentation_header": "",
        "proof_length": 272 + 32 * u, "issuer": "i", "verification_method": "vm",
        "disclosed": disclosed or {"age_over_18": True},
    }
    observation.update(extra)
    return {"verifier_id": "v0", "answered": True, "observation": observation,
            "truth": {"prover_id": prover, "key_id": "k", "presentation_index": index, "claim_set": None}}


def none(prover, index=0):
    return {"verifier_id": "v0", "answered": False, "observation": None,
            "truth": {"prover_id": prover, "key_id": "k", "presentation_index": index,
                      "claim_set": None, "reason": "no claim set can be satisfied"}}


# p1, p2 share a tuple; p3 is alone; p4, p5 cannot answer.
RECORDS = [obs("p1"), obs("p2"), obs("p3", u=2), none("p4"), none("p5")]


def test_partition_and_anonymity_sets():
    part = pa.partition(RECORDS, CORE, "class")
    assert part.anonymity_sets() == [2, 2, 1, 2, 2]
    excluded = pa.partition(RECORDS, CORE, "excluded")
    assert excluded.anonymity_sets() == [2, 2, 1]
    assert excluded.provers == ["p1", "p2", "p3"]


def test_metrics():
    m = pa.metrics(pa.partition(RECORDS, CORE, "class"), 5)
    assert (m.n, m.provers, m.records, m.classes) == (5, 5, 5, 3)
    assert m.unique_fraction == pytest.approx(1 / 5)
    assert (m.min_set, m.median_set, m.max_set) == (1, 2.0, 2)
    assert m.mean_set == pytest.approx(9 / 5)
    assert m.mean_log2_set == pytest.approx(4 / 5)
    assert m.degree == pytest.approx((4 / 5) / math.log2(5))
    e = pa.metrics(pa.partition(RECORDS, CORE, "excluded"), 5)
    assert (e.n, e.provers, e.records, e.classes) == (5, 3, 3, 2)
    assert e.unique_fraction == pytest.approx(1 / 3)


def test_metrics_edge_cases():
    m = pa.metrics(pa.partition([none("p1")], CORE, "excluded"), 1)
    assert (m.provers, m.records, m.degree) == (0, 0, None)
    one = pa.metrics(pa.partition([obs("p1")], CORE, "class"), 1)
    assert one.degree is None and one.unique_fraction == 1.0


def test_only_selected_fields_matter():
    records = [obs("p1", disclosed={"resident_country": "PT"}), obs("p2", disclosed={"resident_country": "DE"})]
    assert pa.partition(records, CORE, "class").anonymity_sets() == [2, 2]
    assert pa.partition(records, CORE + ("disclosed",), "class").anonymity_sets() == [1, 1]
    # A fresh presentation header per proof makes every presentation unique.
    fresh = [obs("p1", presentation_header="aa"), obs("p2", presentation_header="bb")]
    assert pa.partition(fresh, CORE + ("presentation_header",), "class").anonymity_sets() == [1, 1]


def test_tuple_key_ignores_dict_order_and_separates_non_answers():
    a = obs("p1", disclosed={"x": 1, "y": 2})
    b = obs("p2", disclosed={"y": 2, "x": 1})
    assert pa.tuple_key(a, ("disclosed",)) == pa.tuple_key(b, ("disclosed",))
    assert pa.tuple_key(none("p3"), CORE) == pa.NON_ANSWER_KEY
    assert pa.tuple_key(a, CORE) != pa.NON_ANSWER_KEY


def test_anonymity_set_counts_provers_not_presentations():
    records = [obs("p1", index=0), obs("p1", index=1), obs("p2")]
    part = pa.partition(records, CORE, "class")
    assert part.anonymity_sets() == [2, 2, 2]
    assert pa.metrics(part, 2).records == 3


def test_prefixes_follow_first_appearance():
    records = [obs("p3"), obs("p1"), none("p2"), obs("p3", index=1)]
    order = pa.prover_order(records)
    assert order == ["p3", "p1", "p2"]
    assert [r["truth"]["prover_id"] for r in pa.prefix(records, order, 1)] == ["p3", "p3"]
    assert pa.n_points((1, 2, 10), 3) == [1, 2, 3]
    assert pa.n_points((3, 5), 3) == [3]


def test_anonymity_sets_never_shrink_as_n_grows():
    records = [obs(f"p{i}", u=i % 3, header=f"h{i % 2}") for i in range(40)]
    records += [none(f"q{i}") for i in range(5)]
    config = pa.AnalysisConfig(n=(5, 10, 20, 30), tuples={"core": CORE})
    results = pa.analyse(records, config)
    for mode in pa.NON_ANSWER_MODES:
        series = [r for r in results if r.non_answers == mode]
        assert [r.metrics.n for r in series] == [5, 10, 20, 30, 45]
        for earlier, later in zip(series, series[1:]):
            for prover, size in earlier.per_prover.items():
                assert later.per_prover[prover] >= size


@pytest.mark.parametrize(
    "raw, message",
    [
        ({"tuples": {}}, "non-empty"),
        ({"tuples": {"t": {"fields": ["shoe_size"]}}}, "unknown observation field"),
        ({"tuples": {"t": {"fields": ["u", "u"]}}}, "twice"),
        ({"tuples": {"t": {"fields": []}}}, "non-empty array"),
        ({"tuples": {"t": {"fields": ["u"], "other": 1}}}, "exactly one key"),
        ({"n": [0], "tuples": {"t": {"fields": ["u"]}}}, "positive integers"),
        ({"bins": 3, "tuples": {"t": {"fields": ["u"]}}}, "unknown key"),
    ],
)
def test_rejects_bad_configs(raw, message):
    with pytest.raises(ValueError, match=message):
        pa.parse_config(raw)


def test_default_config_loads():
    config = pa.load_config(REPO / "configs/analysis/default.toml")
    assert config.tuples["core"] == CORE
    assert "presentation_header" not in config.tuples["full"]


def test_rejects_mixed_verifiers(tmp_path):
    path = tmp_path / "o.jsonl"
    other = obs("p2")
    other["verifier_id"] = "v1"
    path.write_text("\n".join(json.dumps(r) for r in [obs("p1"), other]) + "\n")
    with pytest.raises(ValueError, match="more than one Verifier"):
        pa.read_observations(path)


def test_cli_writes_outputs(tmp_path):
    path = tmp_path / "o.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in RECORDS) + "\n")
    config = tmp_path / "a.toml"
    config.write_text('n = [2]\n[tuples.core]\nfields = ["u", "total_statements", "selective_indexes", "header"]\n')
    out = tmp_path / "out"
    assert pa.main(["--observations", str(path), "--config", str(config), "--out-dir", str(out), "--per-prover"]) == 0
    summary = list(csv.DictReader((out / "summary.csv").open()))
    assert [(r["non_answers"], r["n"], r["classes"]) for r in summary] == [
        ("class", "2", "1"), ("excluded", "2", "1"), ("class", "5", "3"), ("excluded", "5", "2")]
    sizes = list(csv.DictReader((out / "class_sizes.csv").open()))
    assert {(r["n"], r["non_answers"], r["class_size"], r["classes"]) for r in sizes if r["n"] == "5"} == {
        ("5", "class", "1", "1"), ("5", "class", "2", "2"), ("5", "excluded", "1", "1"), ("5", "excluded", "2", "1")}
    per_prover = list(csv.DictReader((out / "per_prover.csv").open()))
    assert {r["prover_id"] for r in per_prover if r["n"] == "5" and r["non_answers"] == "excluded"} == {"p1", "p2", "p3"}
    meta = json.loads((out / "meta.json").read_text())
    assert meta["verifier_id"] == "v0" and len(meta["observations_sha256"]) == 64


@pytest.mark.skipif(shutil.which("node") is None, reason="needs Node.js for the harness")
def test_full_pipeline(tmp_path):
    """Generate, issue, present, observe, analyse: the stages fit together."""
    pop = tmp_path / "pop.jsonl"
    popgen.main(["--config", str(REPO / "configs/populations/eu-default.toml"), "--n", "16", "--seed", "3",
                 "--out", str(pop)])

    def node(package, *args):
        result = subprocess.run(["node", str(REPO / f"packages/{package}/src/cli.ts"), *args],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    node("issuer", "keygen", "--key-id", "k", "--out-dir", str(tmp_path))
    node("issuer", "issue", "--config", str(REPO / "configs/examples/pid-age.toml"), "--key",
         str(tmp_path / "k.key.json"), "--population", str(pop), "--out", str(tmp_path / "c.jsonl"), "--no-verify")
    node("prover", "present", "--policy", str(REPO / "configs/examples/age-check.toml"), "--public-key",
         str(tmp_path / "k.pub.json"), "--credentials", str(tmp_path / "c.jsonl"),
         "--out", str(tmp_path / "p.jsonl"), "--no-verify")
    node("verifier", "observe", "--public-key", str(tmp_path / "k.pub.json"), "--presentations",
         str(tmp_path / "p.jsonl"), "--out", str(tmp_path / "o.jsonl"))

    out = tmp_path / "analysis"
    assert pa.main(["--observations", str(tmp_path / "o.jsonl"), "--config",
                    str(REPO / "configs/analysis/default.toml"), "--out-dir", str(out)]) == 0
    summary = list(csv.DictReader((out / "summary.csv").open()))
    final = [r for r in summary if r["n"] == "16" and r["non_answers"] == "class"]
    assert {r["tuple"] for r in final} == {"core", "core_values", "full"}
    assert all(int(r["provers"]) == 16 for r in final)
