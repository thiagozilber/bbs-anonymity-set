# bbs-anonymity-set

Measurement harness for the TCC: how far a compliant BBS credential deployment
narrows a Prover population, using only what a Verifier computes while
verifying a presentation (U, the message count, the disclosed index set and the
header).

## Layout

| Path | Contents | Status |
|---|---|---|
| `crates/common` | Types shared by all roles (key files, population and credential records, message encoding) and the wrapper over ZKryptium | done |
| `crates/issuer` | Issuer CLI: key generation and issuance | done |
| `crates/prover` | Prover CLI: credential check; presentation generation under a disclosure policy to follow | `check` only |
| `crates/verifier` | Verification and observation-tuple logging | not started |
| `analysis/` | Python: population generator, partition analysis | not started |
| `configs/examples/` | Example deployment policies | |
| `data/examples/` | Example population | |

New crates under `crates/` join the workspace automatically.

## Build and test

```sh
cargo test
cargo build --release
```

## Issuer

```sh
# Key pair. --seed gives a reproducible key for experiments; omit it for a random one.
issuer keygen --key-id issuer-0 --out-dir out [--seed <hex, >= 32 octets>] [--ciphersuite BLS12-381-SHA-256]

# One credential per population record.
issuer issue --config configs/examples/pid-age.toml --key out/issuer-0.key.json \
             --population data/examples/population.jsonl --out out/credentials.jsonl
```

`keygen` writes `<key-id>.key.json` (contains the secret key; created with
mode 0600 on Unix) and `<key-id>.pub.json`. `issue` verifies every signature
after signing unless `--no-verify` is passed, and prints the number of
credentials per header value and per message count.

## Prover

```sh
# Verify issued credentials against the Issuer's public key, as a Prover does on receipt.
prover check --public-key out/issuer-0.pub.json --credentials out/credentials.jsonl
```

Runs the draft's `Verify` on every credential, lists each one that fails with
its `prover_id`, and exits non-zero if any fail. This checks the Issuer's
signature; it is not presentation verification (`ProofVerify`), which belongs
to the Verifier.

## Issuer details

### Deployment policy (`--config`)

Everything the Issuer decides lives in one TOML file, so each point in a sweep
is one config. See `configs/examples/pid-age.toml`.

- `header.template`: the BBS header, rendered per credential and encoded as
  UTF-8. `{name}` takes the Prover's value for attribute `name`; the attribute
  does not have to be signed. A template with no placeholders gives one header
  value for the whole population.
- `schema.fields`: attributes in message-index order, each optionally
  `optional = true`.
- `schema.absent_optional`: `omit` leaves out an absent optional attribute,
  so the message count varies and later attributes change index; `pad` signs
  `<name>=` in its slot, so every credential has the same message count and
  layout.

### File formats

Population (input), one JSON object per line. Values must be JSON scalars;
`null` counts as absent. Attributes outside the schema and the header template
are rejected.

```json
{"prover_id": "p0001", "attributes": {"birth_date": "1994-03-12", "issuing_country": "BR"}}
```

Credentials (output), one JSON object per line. `prover_id` is the ground-truth
label for the analysis and is never signed. `header` and `signature` are hex;
`messages` are the signed octet strings, in index order.

```json
{"prover_id": "p0001", "key_id": "issuer-0", "ciphersuite": "BLS12-381-SHA-256",
 "header": "7069642d6167652f76312f4252", "messages": ["birth_date=1994-03-12", "issuing_country=BR"],
 "signature": "b13a..."}
```

## Design notes

- **BBS implementation.** ZKryptium, pinned to `=0.7.1`. That release cites
  draft-irtf-cfrg-bbs-signatures-12; its code and test fixtures are identical
  to 0.7.0, which cited draft-10. `crates/common/src/bbs.rs` has known-answer
  tests against the draft's BLS12-381-SHA-256 key and signature fixtures.
- **Signing input.** The Issuer signs an ordered message array with an
  explicit header, as the core draft defines. The W3C `bbs-2023` cryptosuite is
  not implemented; it would compute the header and messages from a JSON-LD
  document and call the same `Sign`.
- **Message encoding.** Each message is the UTF-8 string `<name>=<value>`, so a
  disclosed message can be read without knowing the credential layout. A
  padded slot (`<name>=`) cannot be told apart from a present attribute whose
  value is the empty string.
- **Determinism.** The draft's `Sign` is deterministic, so the same key, policy
  and population always give the same credentials. Seeded keys are for
  reproducible experiments only.
- **Performance.** About 10 ms per credential single-threaded on a 2-core
  machine, about 23 ms with verification. ZKryptium recomputes the generators
  on every `Sign` call. Issuance is not parallelized yet.
