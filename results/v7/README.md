# V7 repeated runs (N = 200, R = 10)

Outputs of the repeated runs reported in the thesis (TCC I, Chapter 4,
validation check V7). Run 01 is also the end-to-end run (V8) and the source of
the worked example in Chapter 3.

## Setup

- Code: commit `bfec36d`. `ba69015` adds tests only, so the runs match it.
- Population: `configs/populations/eu-default.toml`, seed 7, N = 200
  (config sha256 `e96300f3…`, as recorded in `pop.jsonl.meta.json`).
- Issuer: `configs/examples/pid-age.toml` (mandatory pointers `/issuer` and
  `/credentialSubject/issuing_country`; absent optional attributes omitted).
  One Issuer key for all runs. Only the public key is kept here.
- Disclosure policy: `configs/examples/age-check.toml` (claim sets
  [adult, country], then [adult, city]; nonce mode; one presentation per
  Prover). 138 of 200 Provers answer.
- Analysis: `configs/analysis/default.toml` (config sha256 `ab601927…`), plus
  a key-independent tuple (u, total_statements, disclosed, issuer,
  verification_method) computed in the summary.
- The Issuer and the Prover ran with `--no-verify`; the observer verified every
  presentation.
- Machine: 2-core Intel Xeon 2.10 GHz VM, Linux, Node.js 22.23.5,
  Python 3.13.18. 25.5–27.3 s per run.
- Only the HMAC keys the library draws per credential changed between runs.

## Files

- `pop.jsonl`, `pop.jsonl.meta.json`: the population.
- `k.pub.json`: the Issuer's public key.
- Per run NN = 01–10: `cNN.jsonl` credentials, `pNN.jsonl` presentations and
  non-answers, `oNN.jsonl` observations, `aNN/` analysis output
  (`summary.csv`, `class_sizes.csv`, `meta.json`).
- `a01/per_prover.csv`: per-Prover anonymity sets for run 01. Run 01's
  analysis was redone later from the same `o01.jsonl` (same sha256 in
  `a01/meta.json`) to add this file.
- `v7_summary.csv`: min and max of each metric over the 10 runs, at N = 200.
- `original-scripts/`: the scripts that made these files, with the paths of the
  machine they ran on. `meta.json` files also record those paths.

## Reproducing

`scripts/v7_runs.sh` and `scripts/v7_summary.py` are the same scripts with
paths relative to the repository:

```sh
npm ci
scripts/v7_runs.sh out/v7          # N = 200, R = 10, seed 7 by default
python3 scripts/v7_summary.py out/v7 > out/v7/v7_summary.csv
```

The population is the same; the credentials, headers and partitions of
key-dependent tuples are not, because the HMAC keys are random. Only the
distribution of their metrics is reproducible, which is what V7 reports.
`python3 scripts/v7_summary.py results/v7` reproduces `v7_summary.csv` from
the files here exactly.

These numbers describe a synthetic, illustrative population. They validate the
suite and are not results about any deployment.
