#!/bin/bash
# V7: one population (config + seed), one Issuer key, R runs of issue/present/observe/analyse.
set -e
REPO=/home/claude/thiagozilber/bbs-anonymity-set
OUT=/home/claude/runs/r10; N=200; R=10; SEED=7
rm -rf $OUT; mkdir -p $OUT
export PYTHONPATH=$REPO/analysis/src
python3 -m bbs_analysis.popgen --config $REPO/configs/populations/eu-default.toml --n $N --seed $SEED --out $OUT/pop.jsonl 2>/dev/null
node $REPO/packages/issuer/src/cli.ts keygen --key-id k --out-dir $OUT >/dev/null 2>&1
for r in $(seq -w 1 $R); do
  s=$(date +%s.%N)
  node $REPO/packages/issuer/src/cli.ts issue --config $REPO/configs/examples/pid-age.toml --key $OUT/k.key.json --population $OUT/pop.jsonl --out $OUT/c$r.jsonl --no-verify 2>/dev/null
  node $REPO/packages/prover/src/cli.ts present --policy $REPO/configs/examples/age-check.toml --public-key $OUT/k.pub.json --credentials $OUT/c$r.jsonl --out $OUT/p$r.jsonl --no-verify 2>/dev/null
  node $REPO/packages/verifier/src/cli.ts observe --public-key $OUT/k.pub.json --presentations $OUT/p$r.jsonl --out $OUT/o$r.jsonl 2>/dev/null
  python3 -m bbs_analysis.partition --observations $OUT/o$r.jsonl --config $REPO/configs/analysis/default.toml --out-dir $OUT/a$r 2>/dev/null
  echo "run $r: $(echo "$(date +%s.%N) - $s" | bc) s"
done
