# bbs-anonymity-set

Measurement harness for the TCC: how far a compliant BBS credential deployment
narrows a Prover population, using only what a Verifier computes while
verifying a presentation (U, the statement count, the disclosed index set and
the header). Credentials use the W3C `bbs-2023` Data Integrity cryptosuite,
through Digital Bazaar's implementation.

## Layout

| Path | Contents | Status |
|---|---|---|
| `packages/common` | Types shared by all roles (key files, population and credential records), the JSON-LD context and offline document loader, and the typed wrappers over Digital Bazaar's libraries | done |
| `packages/issuer` | Issuer CLI: key generation and issuance | done |
| `packages/prover` | Prover CLI: base-proof check and presentation generation under a disclosure policy | done |
| `packages/verifier` | Presentation verification and observation-tuple logging | not started |
| `analysis/` | Python: population generator, partition analysis | not started |
| `configs/examples/` | Example deployment policies | |
| `data/examples/` | Example population | |

## Build and test

Needs Node.js 22.18 or newer, which runs TypeScript directly (type
stripping), so there is no build step.

```sh
npm install
npm run check        # typecheck, then all tests
npm test             # tests only (vitest)
```

## Issuer

```sh
# Key pair. --seed gives a reproducible key for experiments; omit it for a random one.
npm run issuer -- keygen --key-id issuer-0 --out-dir out [--seed <hex, >= 32 octets>] [--controller <url>]

# One credential per population record.
npm run issuer -- issue --config configs/examples/pid-age.toml --key out/issuer-0.key.json \
                        --population data/examples/population.jsonl --out out/credentials.jsonl
```

`keygen` writes `<key-id>.key.json` (contains the secret key; created with
mode 0600) and `<key-id>.pub.json`. The Issuer's id (`controller`) defaults to
`https://issuer.example/issuers/<key-id>`; give several keys the same
`--controller` to model one Issuer with several keys. The verification method
id is `<controller>#<publicKeyMultibase>`.

`issue` checks every base proof after signing unless `--no-verify` is passed,
and prints the number of credentials per BBS header value, per message count L
and per total statement count.

## Prover

```sh
# Check received credentials against the Issuer's public key.
npm run prover -- check --public-key out/issuer-0.pub.json --credentials out/credentials.jsonl
```

Recomputes each base proof's BBS header and messages from the credential, runs
the draft's `Verify`, lists each failure with its `prover_id`, and exits
non-zero if any fail. This is not presentation verification, which belongs to
the Verifier.

```sh
# Answer a Verifier's query from each credential.
npm run prover -- present --policy configs/examples/age-check.toml --public-key out/issuer-0.pub.json \
                          --credentials out/credentials.jsonl --out out/presentations.jsonl
```

Derives `bbs-2023` disclosure proofs under the disclosure policy, checks each
with the library's verifier unless `--no-verify` is passed, and prints the
number of presentations per claim set, per U and per disclosed message count.
Provers that cannot answer the query are listed with the reason and make no
presentation; that is an outcome, not an error.

### Disclosure policy (`--policy`)

What the Verifier asks for and how the Prover answers, in one TOML file per
sweep point. See `configs/examples/age-check.toml`.

- `query`: a subset of a DCQL Credential Query (OpenID4VP §6) for one
  credential.
  - `claims`: each with `id`, `path` (a claims path pointer of strings and
    non-negative integers) and optional `values`. A claim whose value is not
    one of `values` counts as absent.
  - `claim_sets`: alternatives in the Verifier's order of preference. The
    Prover presents the first option it can satisfy.
  - Without `claim_sets`, every claim is required. Without `claims`, only the
    mandatory statements are disclosed.
- `presentation.count`: presentations per credential (default 1).
- `presentation.header`: the presentation header.
  - `empty` (default);
  - `random`: 32 fresh octets per proof, chosen by the Prover;
  - `nonce`: 32 fresh octets per proof, chosen by the Verifier and recorded
    as `verifier_nonce`;
  - `fixed`: the same value (`header_value`, hex) in every proof, which
    models presentation header reuse.

### Presentations (output)

One JSON object per line. The Verifier observer reads only `presentation`
and `verifier_nonce`, which a real Verifier has; `prover_id`,
`presentation_index` and `claim_set` are ground truth for the analysis.

```json
{"prover_id": "p0001", "key_id": "issuer-0", "presentation_index": 0, "claim_set": 0,
 "verifier_nonce": "7b67...", "presentation": {"credentialSubject": {"issuing_country": "BR", "age_over_18": true,
 "resident_country": "BR"}, "proof": {"cryptosuite": "bbs-2023", "proofValue": "u2V0D..."}, "...": "..."}}
```

## Issuer details

### Deployment policy (`--config`)

Everything the Issuer decides lives in one TOML file, so each point in a sweep
is one config. See `configs/examples/pid-age.toml`.

- `schema.fields`: attributes a credential may carry, each optionally
  `optional = true`. Names must be terms of the PID context. The order does not
  set message indexes; the canonical N-Quad order does.
- `schema.absent_optional`: only `omit`. An absent optional attribute is left
  out, so L is one smaller.
- `proof.mandatory_pointers`: JSON Pointers to statements that are always
  disclosed. Their N-Quads are hashed into the BBS header instead of being BBS
  messages. A pointer into `credentialSubject` must name a required field.

### Credentials

Each population record becomes a VC Data Model 2.0 credential of type
`PidCredential`, with the record's attributes in `credentialSubject`. The
JSON-LD context (`packages/common/src/contexts.ts`) is ours: term names follow
the EUDI PID Rulebook, which defines only mdoc and SD-JWT VC encodings, and
`age_over_18` comes from the German PID's national extension. Contexts and key
documents are served by an offline document loader; nothing is fetched.

### File formats

Population (input), one JSON object per line. Values must be JSON scalars;
`null` counts as absent. Attributes outside the schema are rejected.

```json
{"prover_id": "p0001", "attributes": {"birth_date": "1994-03-12", "issuing_country": "BR"}}
```

Credentials (output), one JSON object per line. `prover_id` is the
ground-truth label for the analysis and is never signed.

```json
{"prover_id": "p0001", "key_id": "issuer-0", "credential": {"@context": ["https://www.w3.org/ns/credentials/v2", "..."],
 "type": ["VerifiableCredential", "PidCredential"], "issuer": "https://issuer.example/issuers/issuer-0",
 "credentialSubject": {"birth_date": "1994-03-12", "issuing_country": "BR"},
 "proof": {"type": "DataIntegrityProof", "cryptosuite": "bbs-2023", "proofValue": "u2V0C..."}}}
```

## Design notes

- **Libraries.** `@digitalbazaar/vc` 7.3.0, `data-integrity`,
  `bbs-2023-cryptosuite` 2.0.1, `di-sd-primitives` 3.3.0 and `bbs-signatures`
  3.1.0. The packages ship no types; `packages/common/types/digitalbazaar.d.ts`
  declares what is used, and only `packages/common/src/bbs.ts` and
  `bbs2023.ts` import them. `packages/common/test/bbs.test.ts` runs the draft's
  BLS12-381-SHA-256 signature and proof fixtures against the core BBS calls.
- **Base-proof check.** The cryptosuite verifies derived proofs only.
  `inspectBaseProof` rebuilds the BBS header and messages the way its sign step
  does (same `di-sd-primitives` calls and HMAC label shuffle), and the tests
  cross-check it against the library's derive and verify.
- **No `created`.** The library deletes `created` from base proofs, so the
  timestamp channel (spec §6.2.4) cannot be exercised with it as-is.
- **Not deterministic.** Each base proof gets a fresh random HMAC key, so
  issuing the same population twice gives different credentials. Counts and
  the header's dependence on content are stable; individual header values and
  index sets are not.
- **Performance.** On a 2-core VM, about 60 ms per credential without the
  check and 140 ms with it; `prover check` about 85 ms per credential;
  `prover present` about 150 ms per presentation without verification and
  280 ms with it. Not parallelized yet.

### Binding channels

- **Header.** `proofHash || mandatoryHash`. `proofHash` depends only on the
  proof options. `mandatoryHash` hashes the mandatory N-Quads, which carry the
  HMAC-shuffled blank node labels. The example credential has two blank nodes
  (the credential and its subject), so credentials with identical mandatory
  content get one of two header values at random, according to which node is
  labelled `b0`. With the example policy that is up to two header values per
  issuing country.
- **Index sets.** The same shuffle changes the canonical order of the N-Quads,
  so message indexes differ across credentials and stay fixed across one
  credential's presentations (spec §6.2.2). The derived proof's label map is
  also the same in every presentation of a credential.
