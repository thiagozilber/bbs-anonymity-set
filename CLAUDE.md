# CLAUDE.md

Context for working on this repo. The README covers usage; this file covers
why things are the way they are.

## What this repo is for

The measurement harness for Thiago's TCC (PUCRS). The thesis measures how far a
compliant BBS credential deployment narrows a Prover population, using only
what a Verifier computes while verifying a presentation: U (from proof size),
the message count, the disclosed index set and the header. Identical
observation tuples define equivalence classes; the results are class-size
distributions and curves over population size N. The partition is exact, so
there is no classifier. The ML branch and all network-layer (Layer 1) features
are deferred to TCC II.

Planned components: population generator (Python), Issuer, Prover, Verifier
observer, analysis (Python). Only the Issuer exists so far.

## Decisions

- **BBS library.** ZKryptium, pinned `=0.7.1`. All BBS calls go through
  `crates/common/src/bbs.rs`; keep the known-answer tests against the draft
  fixtures passing.
- **Signing input.** The Issuer signs an ordered message array with an
  explicit header, as the core draft defines (messages are UTF-8
  `<name>=<value>`). The W3C `bbs-2023` cryptosuite may be added later as a
  layer in front of the same `Sign`. It does not change the scheme. If it is
  added:
  - use `featureOption = "baseline"` only; the optional features switch to
    the Blind BBS and per-Verifier-linkability drafts, which are different
    schemes;
  - the header becomes `proofHash || mandatoryHash`, so it carries exactly
    what the proof options and mandatory statements carry and is not an
    independent channel;
  - only non-mandatory statements are BBS messages, so L counts those, and
    the total statement count is mandatory count plus L.
- **No OpenID4VP or OpenID4VCI.** The tuple is measured at the credential
  boundary (the inputs to `ProofVerify`). The Verifier observer takes
  presentation objects, not network connections, so a transport can be added
  for TCC II without changing it. The disclosure policy is defined by us in
  config, modeled on DCQL (including `claim_sets`).
- **Issuer.** Batch CLI, not a service. All Issuer-side deployment policy
  (header template, schema order, omit or pad for absent optional attributes)
  lives in one TOML file per sweep point.
- **Ground truth.** `prover_id` travels with every record for the analysis and
  is never signed.

## Open items

- **Draft version.** The thesis text cites draft-10. Draft-12 (28 Sept 2026)
  is the latest; ZKryptium 0.7.1 cites it, with code and fixtures identical to
  0.7.0 (draft-10). Compare draft-12 against draft-10 for the §5.1 header
  guidance and the proof-size formula before changing the citation.
- **Issuance speed.** About 10 ms per credential single-threaded on a 2-core
  machine, about 23 ms with verification. ZKryptium recomputes the generators
  on every `Sign`, and its internal signing function is private. Parallelize
  across records if the N sweep needs it.

## Conventions

- `cargo fmt`, `cargo clippy --all-targets` with no warnings, and `cargo test`
  before every commit.
- Anything that crosses a process boundary (keys, population, credentials) is
  a type in `crates/common` and is written as JSON or JSON Lines.
- Files holding secret key material are written with `write_json_private`
  (mode 0600), never `write_json`.
- Commits carry no Claude co-author or session trailers.
- New crates go under `crates/`; the workspace picks them up automatically.
- Thiago writes the thesis prose himself. Code comments and docs here should
  state things plainly.
