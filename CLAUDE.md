# CLAUDE.md

Context for working on this repo. The README covers usage; this file covers
why things are the way they are.

## What this repo is for

The measurement harness for Thiago's TCC (PUCRS). The thesis measures how far a
compliant BBS credential deployment narrows a Prover population, using only
what a Verifier computes while verifying a presentation: U (from proof size),
the total statement count, the disclosed index set and the header. Identical
observation tuples define equivalence classes; the results are class-size
distributions and curves over population size N. The partition is exact, so
there is no classifier. The ML branch and all network-layer (Layer 1) features
are deferred to TCC II.

Planned components: population generator (Python), Issuer, Prover, Verifier
observer, analysis (Python). The population generator, Issuer, Prover
(`check`, `present`) and Verifier observer are done. The partition analysis
(Python, under `analysis/`) is next.

## Decisions

- **Stack.** TypeScript on Digital Bazaar's `bbs-2023` implementation, which
  passes the W3C vc-di-bbs test suite. Implementing `bbs-2023` ourselves
  (JSON-LD, RDFC-1.0, selective-disclosure primitives, CBOR proof encoding)
  is not the thesis contribution. The earlier Rust harness on ZKryptium is in
  git history; there is no Rust cross-check.
- **One place for the libraries.** Digital Bazaar's packages are untyped. Only
  `packages/common/src/bbs.ts` (core BBS) and `bbs2023.ts` (cryptosuite, VC,
  Data Integrity, di-sd-primitives) import them, declared in
  `packages/common/types/digitalbazaar.d.ts`. Keep the draft fixture tests in
  `packages/common/test/bbs.test.ts` passing.
- **Base-proof check is ours.** The cryptosuite has no Holder-side check of a
  base proof. `inspectBaseProof` repeats the cryptosuite's sign-side steps
  with the HMAC key from the proof; the tests check it against the library's
  derive and verify. If the library is upgraded, re-read its `sign.js` and
  `sdFunctions.js` and compare.
- **Baseline only.** `featureOption = "baseline"`; the optional features use
  the Blind BBS and per-Verifier-linkability drafts, which are different
  schemes.
- **Header.** `proofHash || mandatoryHash`. It is not an independent channel,
  but it is also not a function of the mandatory content alone: the mandatory
  N-Quads carry the HMAC-shuffled blank node labels, so identical content
  splits into up to (number of blank nodes)! header values. L counts only
  non-mandatory statements; total statement count = mandatory count + L.
- **Vocabulary.** Our own JSON-LD context with term names from the EUDI PID
  Rulebook (`age_over_18` from the German extension, since EU-level PID
  versions dropped age attributes). The PID Rulebook has no JSON-LD encoding.
- **No OpenID4VP or OpenID4VCI.** The tuple is measured at the credential
  boundary. The Verifier observer takes presentation objects, not network
  connections, so a transport can be added for TCC II without changing it.
  The disclosure policy is defined by us in config, modeled on DCQL
  (including `claim_sets`).
- **Population generator.** Python (stdlib only) in `analysis/`, managed with
  uv. Distributions come from a TOML config; the default
  (`configs/populations/eu-default.toml`) uses EU member states, since PIDs
  are issued by them, and its numbers are plausible but not sourced. Optional
  residence attributes are nested (city only with country). Populations are
  prefix-consistent: record i is seeded by (seed, i), so curves over N differ
  only by the added Provers.
- **Issuer.** Batch CLI, not a service. All Issuer-side policy lives in one
  TOML file per sweep point.
- **Prover presentations.** Disclosure policy is one TOML file per sweep
  point. The Prover follows DCQL's recommendation and presents the first
  `claim_sets` option it can satisfy; one that satisfies none makes no
  presentation, which is recorded as an outcome. Presentation header modes:
  `empty`, `random` (Prover-chosen), `nonce` (Verifier-chosen, recorded as
  `verifier_nonce`), `fixed` (reuse). Presentations per credential are
  configurable, default 1.
- **Non-answers.** A Prover that cannot answer writes one non-answer record
  per request; the observer passes them through. Whether "no presentation" is
  its own class in the partition is decided in the analysis.
- **Verifier observer.** Records every channel raw (counts, both index sets,
  header, label map, relabelled revealed N-Quads, presentation header,
  disclosed values, issuer and key). It does not choose the tuple; the
  analysis does, so changing the tuple needs no rerun. Presentations that fail
  verification are left out and make the run exit non-zero, since in the
  harness they mean a bug.
- **Collusion.** One observer run per Verifier, stamped with `--verifier-id`.
  RP+RP'-U is modelled by joining observation files in the analysis, so the
  observer stays a single honest Verifier and the join method can vary
  without reruns.
- **Ground truth.** `prover_id` travels with every record for the analysis and
  is never signed. In observation records it lives under `truth`, apart from
  `observation`.

## Open items

- **`pad`.** `absent_optional = "pad"` has no `bbs-2023` equivalent and is
  rejected by the config loader. Placeholder values are one option.
- **Proof options as a channel.** The library deletes `created` from base
  proofs, so spec §6.2.4 cannot be exercised as-is. Other proof options and
  the number of Issuer keys (§6.2.1, via `keygen --controller`) are not in the
  config yet.
- **Reproducibility.** The HMAC key is random per credential and the library
  gives no way to supply it, so runs are not reproducible credential by
  credential. Supplying it would mean our own sign cryptosuite object built on
  the same primitives.
- **Core BBS baseline.** Whether to also run core BBS next to `bbs-2023`, to
  isolate what the binding adds. Only if it comes almost free.
- **Large N.** About 60 ms per credential without the check. Options: worker
  threads, or run the `bbs-2023` transformation without `Sign`/`ProofGen` for
  large N and confirm the tuples with full runs on smaller N (a method choice
  to state in the thesis).
- **Draft version.** The thesis cites draft-10; draft-12 (28 Sept 2026) is the
  latest. `bbs-signatures` comments cite draft-06 but its outputs match the
  current fixtures. Compare draft-12 against draft-10 for the §5.1 header
  guidance and the proof-size formula before changing the citation.

## Conventions

- `npm run check` (typecheck, TypeScript tests, Python tests) before every
  commit.
- Node runs the TypeScript directly, so code must be erasable syntax only (no
  enums, namespaces or parameter properties); `erasableSyntaxOnly` enforces it.
  Relative imports use `.ts` extensions.
- Anything that crosses a process boundary (keys, population, credentials) is
  a type in `packages/common/src/types.ts` and is written as JSON or JSON
  Lines.
- Files holding secret key material are written with `writeJsonPrivate`
  (mode 0600), never `writeJson`.
- Commits carry no Claude co-author or session trailers.
- Thiago writes the thesis prose himself. Code comments and docs here should
  state things plainly.
