import copy
import datetime as dt
import json
import shutil
import subprocess
import tomllib
from collections import Counter
from pathlib import Path

import pytest

from bbs_analysis import popgen

REPO = Path(__file__).resolve().parents[2]
DEFAULT = REPO / "configs/populations/eu-default.toml"
RAW = tomllib.loads(DEFAULT.read_text(encoding="utf-8"))


def config(**changes):
    """The default config with top-level or dotted-path overrides."""
    raw = copy.deepcopy(RAW)
    for path, value in changes.items():
        *parents, last = path.split("__")
        table = raw
        for p in parents:
            table = table[p]
        table[last] = value
    return popgen.parse_config(raw)


CFG = config()


def test_deterministic_and_seed_dependent():
    assert popgen.generate(CFG, 7, 50) == popgen.generate(CFG, 7, 50)
    assert popgen.generate(CFG, 7, 50) != popgen.generate(CFG, 8, 50)


def test_prefix_consistent():
    small, large = popgen.generate(CFG, 3, 40), popgen.generate(CFG, 3, 400)
    assert large[:40] == small
    assert popgen.generate_record(CFG, 3, 399) == large[399]


def test_prover_ids_do_not_depend_on_n():
    assert [r["prover_id"] for r in popgen.generate(CFG, 1, 3)] == ["p0000000", "p0000001", "p0000002"]


def test_records_are_consistent():
    for r in popgen.generate(CFG, 11, 2000):
        a = r["attributes"]
        assert set(a) <= {
            "family_name", "given_name", "birth_date", "age_over_18",
            "nationality", "resident_country", "resident_city", "issuing_country",
        }
        birth = dt.date.fromisoformat(a["birth_date"])
        age = popgen._age_on(birth, CFG.as_of)
        assert 0 <= age <= 95
        assert a["age_over_18"] == (age >= 18)
        assert a["family_name"] in CFG.names[a["issuing_country"]].family
        if "resident_city" in a:
            assert "resident_country" in a
            assert a["resident_city"] in CFG.cities[a["resident_country"]].values


def test_distributions_roughly_match_config():
    records = popgen.generate(CFG, 5, 5000)
    counts = Counter(r["attributes"]["issuing_country"] for r in records)
    for country, weight in zip(CFG.issuing_country.values, CFG.issuing_country.weights):
        assert abs(counts[country] / 5000 - weight) < 0.03
    with_country = sum("resident_country" in r["attributes"] for r in records)
    assert abs(with_country / 5000 - 0.8) < 0.03
    minors = sum(not r["attributes"]["age_over_18"] for r in records)
    assert abs(minors / 5000 - 18 / 100) < 0.03


def test_age_band_edges():
    cfg = config(age__bands=[{"min": 18, "max": 18, "weight": 1}])
    for r in popgen.generate(cfg, 2, 300):
        assert popgen._age_on(dt.date.fromisoformat(r["attributes"]["birth_date"]), cfg.as_of) == 18
    cfg = config(age__bands=[{"min": 17, "max": 17, "weight": 1}])
    assert not any(r["attributes"]["age_over_18"] for r in popgen.generate(cfg, 2, 300))


def test_residence_probabilities_at_the_extremes():
    none = config(residence__country_present=0)
    assert not any("resident_country" in r["attributes"] for r in popgen.generate(none, 1, 200))
    all_ = config(residence__country_present=1, residence__city_present=1, residence__same_as_issuing=1)
    for r in popgen.generate(all_, 1, 200):
        a = r["attributes"]
        assert a["resident_country"] == a["issuing_country"]
        assert "resident_city" in a


def test_single_country_never_samples_another():
    cfg = config(
        issuing_country={"PT": 1},
        nationality__same_as_issuing=0,
        residence__same_as_issuing=0,
        residence__cities={"PT": RAW["residence"]["cities"]["PT"]},
        names={"PT": RAW["names"]["PT"]},
    )
    for r in popgen.generate(cfg, 1, 50):
        assert r["attributes"]["nationality"] == "PT"


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"as_of": "2026-10-01"}, "as_of"),
        ({"issuing_country": {}}, "must not be empty"),
        ({"issuing_country": {"DE": -1}}, "non-negative"),
        ({"issuing_country": {"DE": 0}}, "all zero"),
        ({"nationality__same_as_issuing": 1.5}, r"\[0, 1\]"),
        ({"age__bands": []}, "non-empty"),
        ({"age__bands": [{"min": 30, "max": 20, "weight": 1}]}, "min <= max"),
        ({"residence__cities": {"BR": {"Pelotas": 1}}}, "not an issuing_country"),
        ({"residence__colour": 1}, "unknown key"),
        ({"names": {}}, "names.DE"),
        ({"shoe_size": 42}, "unknown key"),
    ],
)
def test_rejects_bad_configs(changes, message):
    with pytest.raises(ValueError, match=message):
        config(**changes)


def test_cli_writes_population_and_metadata(tmp_path):
    out = tmp_path / "pop.jsonl"
    assert popgen.main(["--config", str(DEFAULT), "--n", "25", "--seed", "4", "--out", str(out)]) == 0
    lines = out.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in lines] == popgen.generate(CFG, 4, 25)
    meta = json.loads((tmp_path / "pop.jsonl.meta.json").read_text())
    assert meta["seed"] == 4 and meta["n"] == 25 and len(meta["config_sha256"]) == 64


@pytest.mark.skipif(shutil.which("node") is None, reason="needs Node.js for the issuer")
def test_issuer_accepts_generated_population(tmp_path):
    pop = tmp_path / "pop.jsonl"
    popgen.main(["--config", str(DEFAULT), "--n", "12", "--seed", "9", "--out", str(pop)])
    issuer = REPO / "packages/issuer/src/cli.ts"
    run = lambda *args: subprocess.run(["node", str(issuer), *args], capture_output=True, text=True)
    assert run("keygen", "--key-id", "k", "--out-dir", str(tmp_path)).returncode == 0
    result = run(
        "issue", "--config", str(REPO / "configs/examples/pid-age.toml"),
        "--key", str(tmp_path / "k.key.json"), "--population", str(pop),
        "--out", str(tmp_path / "creds.jsonl"),
    )
    assert result.returncode == 0, result.stderr
    assert len((tmp_path / "creds.jsonl").read_text().splitlines()) == 12
