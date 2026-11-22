#!/bin/bash
# Repeated runs (validation check V7): one population (config + seed), one
# Issuer key, R runs of issue / present / observe / analyse. Only the HMAC keys
# the library draws per credential change between runs.
#
# Usage: scripts/v7_runs.sh [OUT] [N] [R] [SEED]
#   OUT   output directory (default out/v7; must not be under results/)
#   N     population size (default 200)
#   R     number of runs (default 10)
#   SEED  population seed (default 7)
#
# Then: python3 scripts/v7_summary.py OUT > OUT/v7_summary.csv
#
# The Issuer and the Prover run with --no-verify to shorten the runs; the
# observer verifies every presentation. The thesis runs (results/v7/) were made
# with results/v7/original-scripts/r10.sh, which is this script with the
# paths of the machine it ran on.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$REPO/out/v7}; N=${2:-200}; R=${3:-10}; SEED=${4:-7}
OUT=$(realpath -m "$OUT")
case "$OUT" in "$REPO"/results*) echo "refusing to write under results/: $OUT" >&2; exit 1;; esac
mkdir -p "$OUT"
rm -rf "${OUT:?}"/*
export PYTHONPATH=$REPO/analysis/src
python3 -m bbs_analysis.popgen --config "$REPO/configs/populations/eu-default.toml" --n "$N" --seed "$SEED" --out "$OUT/pop.jsonl"
node "$REPO/packages/issuer/src/cli.ts" keygen --key-id k --out-dir "$OUT" >/dev/null
for r in $(seq -w 1 "$R"); do
  s=$(date +%s.%N)
  node "$REPO/packages/issuer/src/cli.ts" issue --config "$REPO/configs/examples/pid-age.toml" --key "$OUT/k.key.json" --population "$OUT/pop.jsonl" --out "$OUT/c$r.jsonl" --no-verify
  node "$REPO/packages/prover/src/cli.ts" present --policy "$REPO/configs/examples/age-check.toml" --public-key "$OUT/k.pub.json" --credentials "$OUT/c$r.jsonl" --out "$OUT/p$r.jsonl" --no-verify
  node "$REPO/packages/verifier/src/cli.ts" observe --public-key "$OUT/k.pub.json" --presentations "$OUT/p$r.jsonl" --out "$OUT/o$r.jsonl"
  python3 -m bbs_analysis.partition --observations "$OUT/o$r.jsonl" --config "$REPO/configs/analysis/default.toml" --out-dir "$OUT/a$r"
  echo "run $r: $(python3 -c "import time; print(round(time.time() - $s, 1))") s" >&2
done
