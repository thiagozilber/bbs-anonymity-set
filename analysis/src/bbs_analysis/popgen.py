"""Synthetic Prover populations for the Issuer.

Each population is drawn from a TOML config of attribute distributions. The
output is the population format `issuer issue` reads: one JSON object per
line, `{"prover_id": ..., "attributes": {...}}`.

Populations are prefix-consistent: record i depends only on the seed and i,
so the population of size N is the first N records of any larger population
with the same config and seed. Curves over N then differ only by the Provers
added at each step.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import random
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENERATOR_VERSION = 1

# Fixed width, so a Prover's id does not depend on N.
PROVER_ID_WIDTH = 7


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Categorical:
    """A distribution over named values. Weights are normalized on load."""

    values: tuple[str, ...]
    weights: tuple[float, ...]

    def sample(self, rng: random.Random, exclude: str | None = None) -> str:
        pairs = [(v, w) for v, w in zip(self.values, self.weights) if v != exclude]
        if not pairs or sum(w for _, w in pairs) == 0:
            raise ValueError(f"no value left to sample after excluding {exclude!r}")
        values, weights = zip(*pairs)
        return rng.choices(values, weights=weights)[0]


@dataclass(frozen=True)
class AgeBand:
    min: int
    max: int
    weight: float


@dataclass(frozen=True)
class Names:
    family: tuple[str, ...]
    given: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    as_of: dt.date
    issuing_country: Categorical
    nationality_same_as_issuing: float
    age_bands: tuple[AgeBand, ...]
    residence_country_present: float
    residence_same_as_issuing: float
    residence_city_present: float
    cities: dict[str, Categorical]
    names: dict[str, Names]


def load_config(path: Path) -> Config:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ValueError(f"{path}: {e}") from e
    try:
        return parse_config(raw)
    except ValueError as e:
        raise ValueError(f"{path}: {e}") from e


def parse_config(raw: dict[str, Any]) -> Config:
    _keys(raw, "config", {"as_of", "issuing_country", "nationality", "age", "residence", "names"})

    as_of = raw.get("as_of")
    if not isinstance(as_of, dt.date) or isinstance(as_of, dt.datetime):
        raise ValueError("as_of must be a TOML date, e.g. as_of = 2026-10-01")

    issuing = _categorical(raw.get("issuing_country"), "issuing_country")
    countries = set(issuing.values)

    nationality = _table(raw.get("nationality", {}), "nationality", {"same_as_issuing"})
    same_nat = _probability(nationality.get("same_as_issuing", 1.0), "nationality.same_as_issuing")

    age = _table(raw.get("age"), "age", {"bands"})
    bands_raw = age.get("bands")
    if not isinstance(bands_raw, list) or not bands_raw:
        raise ValueError("age.bands must be a non-empty array of tables")
    bands = []
    for i, b in enumerate(bands_raw):
        t = _table(b, f"age.bands[{i}]", {"min", "max", "weight"})
        lo, hi, w = t.get("min"), t.get("max"), t.get("weight")
        if not (isinstance(lo, int) and isinstance(hi, int) and 0 <= lo <= hi <= 130):
            raise ValueError(f"age.bands[{i}]: need integers 0 <= min <= max <= 130")
        bands.append(AgeBand(lo, hi, _weight(w, f"age.bands[{i}].weight")))
    if sum(b.weight for b in bands) == 0:
        raise ValueError("age.bands weights are all zero")

    residence = _table(
        raw.get("residence", {}),
        "residence",
        {"country_present", "same_as_issuing", "city_present", "cities"},
    )
    cities_raw = _table(residence.get("cities", {}), "residence.cities", None)
    cities = {}
    for country, table in cities_raw.items():
        if country not in countries:
            raise ValueError(f"residence.cities.{country}: not an issuing_country")
        cities[country] = _categorical(table, f"residence.cities.{country}")

    names_raw = _table(raw.get("names"), "names", None)
    names = {}
    for country in sorted(countries):
        t = _table(names_raw.get(country), f"names.{country}", {"family", "given"})
        family, given = t.get("family"), t.get("given")
        for key, value in (("family", family), ("given", given)):
            if not isinstance(value, list) or not value or not all(isinstance(s, str) and s for s in value):
                raise ValueError(f"names.{country}.{key} must be a non-empty array of strings")
        names[country] = Names(tuple(family), tuple(given))
    for country in names_raw:
        if country not in countries:
            raise ValueError(f"names.{country}: not an issuing_country")

    return Config(
        as_of=as_of,
        issuing_country=issuing,
        nationality_same_as_issuing=same_nat,
        age_bands=tuple(bands),
        residence_country_present=_probability(residence.get("country_present", 1.0), "residence.country_present"),
        residence_same_as_issuing=_probability(residence.get("same_as_issuing", 1.0), "residence.same_as_issuing"),
        residence_city_present=_probability(residence.get("city_present", 1.0), "residence.city_present"),
        cities=cities,
        names=names,
    )


def _keys(value: dict[str, Any], where: str, allowed: set[str]) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{where}: unknown key {unknown[0]!r}")


def _table(value: Any, where: str, allowed: set[str] | None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be a table")
    if allowed is not None:
        _keys(value, where, allowed)
    return value


def _weight(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"{where} must be a non-negative number")
    return float(value)


def _probability(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise ValueError(f"{where} must be a number in [0, 1]")
    return float(value)


def _categorical(value: Any, where: str) -> Categorical:
    t = _table(value, where, None)
    if not t:
        raise ValueError(f"{where} must not be empty")
    weights = {k: _weight(v, f"{where}.{k}") for k, v in t.items()}
    total = sum(weights.values())
    if total == 0:
        raise ValueError(f"{where}: weights are all zero")
    return Categorical(tuple(weights), tuple(w / total for w in weights.values()))


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def prover_id(index: int) -> str:
    return f"p{index:0{PROVER_ID_WIDTH}d}"


def generate_record(config: Config, seed: int, index: int) -> dict[str, Any]:
    """Record `index` of the population. Depends only on (config, seed, index)."""
    # String seeds are hashed with SHA-512, so this does not depend on
    # PYTHONHASHSEED or the Python build.
    rng = random.Random(f"bbs-anonymity-set/popgen/v{GENERATOR_VERSION}/{seed}/{index}")

    issuing = config.issuing_country.sample(rng)
    if len(config.issuing_country.values) > 1 and rng.random() >= config.nationality_same_as_issuing:
        nationality = config.issuing_country.sample(rng, exclude=issuing)
    else:
        nationality = issuing

    birth_date = _birth_date(config, rng)
    names = config.names[issuing]
    attributes: dict[str, Any] = {
        "family_name": rng.choice(names.family),
        "given_name": rng.choice(names.given),
        "birth_date": birth_date.isoformat(),
        "age_over_18": _age_on(birth_date, config.as_of) >= 18,
        "nationality": nationality,
    }

    # Nested optional attributes: a city only when a country is present.
    if rng.random() < config.residence_country_present:
        if len(config.issuing_country.values) > 1 and rng.random() >= config.residence_same_as_issuing:
            resident_country = config.issuing_country.sample(rng, exclude=issuing)
        else:
            resident_country = issuing
        attributes["resident_country"] = resident_country
        cities = config.cities.get(resident_country)
        if cities is not None and rng.random() < config.residence_city_present:
            attributes["resident_city"] = cities.sample(rng)

    attributes["issuing_country"] = issuing
    return {"prover_id": prover_id(index), "attributes": attributes}


def generate(config: Config, seed: int, n: int) -> list[dict[str, Any]]:
    return [generate_record(config, seed, i) for i in range(n)]


def _birth_date(config: Config, rng: random.Random) -> dt.date:
    band = rng.choices(config.age_bands, weights=[b.weight for b in config.age_bands])[0]
    # Birth dates for which the age on as_of is in [band.min, band.max].
    latest = _years_before(config.as_of, band.min)
    earliest = _years_before(config.as_of, band.max + 1) + dt.timedelta(days=1)
    return earliest + dt.timedelta(days=rng.randrange((latest - earliest).days + 1))


def _years_before(day: dt.date, years: int) -> dt.date:
    try:
        return day.replace(year=day.year - years)
    except ValueError:  # 29 February in a non-leap year
        return day.replace(year=day.year - years, day=28)


def _age_on(birth: dt.date, day: dt.date) -> int:
    return day.year - birth.year - ((day.month, day.day) < (birth.month, birth.day))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def summary(records: list[dict[str, Any]]) -> str:
    issuing = Counter(r["attributes"]["issuing_country"] for r in records)
    pattern = Counter(
        ("country" if "resident_country" in r["attributes"] else "-")
        + "/"
        + ("city" if "resident_city" in r["attributes"] else "-")
        for r in records
    )
    adults = sum(r["attributes"]["age_over_18"] for r in records)
    lines = [f"  issuing countries: {len(issuing)}"]
    lines += [f"    {n:>8}  {c}" for c, n in sorted(issuing.items())]
    lines.append("  optional residence attributes (country/city):")
    lines += [f"    {n:>8}  {p}" for p, n in sorted(pattern.items())]
    lines.append(f"  age_over_18: {adults} true, {len(records) - adults} false")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="popgen",
        description="Generate a synthetic Prover population (JSON Lines) for issuer issue.",
    )
    parser.add_argument("--config", required=True, type=Path, help="population config (TOML)")
    parser.add_argument("--n", required=True, type=int, help="population size")
    parser.add_argument("--seed", required=True, type=int, help="seed; same config and seed give the same Provers")
    parser.add_argument("--out", required=True, type=Path, help="output population (JSON Lines)")
    args = parser.parse_args(argv)

    if args.n < 1:
        parser.error("--n must be at least 1")
    try:
        config = load_config(args.config)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    records = generate(config, args.seed, args.n)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")

    meta_path = args.out.with_name(args.out.name + ".meta.json")
    meta = {
        "generator_version": GENERATOR_VERSION,
        "config": str(args.config),
        "config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
        "seed": args.seed,
        "n": args.n,
    }
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {len(records)} Provers to {args.out} (metadata in {meta_path})", file=sys.stderr)
    print(summary(records), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
