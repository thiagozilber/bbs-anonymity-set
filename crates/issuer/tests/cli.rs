//! End-to-end: run the `issuer` binary on the example config and population.

use common::{CredentialRecord, PublicKeyFile, bbs, read_json, read_jsonl};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn issuer() -> Command {
    Command::new(env!("CARGO_BIN_EXE_issuer"))
}

fn keygen(dir: &Path, extra: &[&str]) -> std::process::Output {
    issuer()
        .args([
            "keygen",
            "--key-id",
            "issuer-0",
            "--seed",
            SEED,
            "--out-dir",
        ])
        .arg(dir)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn issues_and_verifies_example_population() {
    let dir = scratch("e2e");
    assert!(keygen(&dir, &[]).status.success());

    let out = dir.join("credentials.jsonl");
    let run = issuer()
        .arg("issue")
        .arg("--config")
        .arg(repo_root().join("configs/examples/pid-age.toml"))
        .arg("--key")
        .arg(dir.join("issuer-0.key.json"))
        .arg("--population")
        .arg(repo_root().join("data/examples/population.jsonl"))
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let public: PublicKeyFile = read_json(&dir.join("issuer-0.pub.json")).unwrap();
    let pk = hex::decode(&public.public_key).unwrap();
    let creds: Vec<CredentialRecord> = read_jsonl(&out).unwrap();
    assert_eq!(creds.len(), 6);

    // Every credential verifies against the public key file alone.
    for c in &creds {
        assert_eq!(c.key_id, "issuer-0");
        bbs::verify(
            c.ciphersuite,
            &pk,
            &c.header_bytes().unwrap(),
            &c.message_bytes(),
            &c.signature_bytes().unwrap(),
        )
        .unwrap_or_else(|e| panic!("{}: {e}", c.prover_id));
    }

    // With absent_optional = "omit", L tracks which optional attributes a Prover has.
    let l: BTreeMap<_, _> = creds
        .iter()
        .map(|c| (c.prover_id.as_str(), c.messages.len()))
        .collect();
    assert_eq!(
        l,
        BTreeMap::from([
            ("p0001", 8),
            ("p0002", 7),
            ("p0003", 6),
            ("p0004", 8),
            ("p0005", 7),
            ("p0006", 6)
        ])
    );

    // One header value per issuing country.
    let mut headers: BTreeMap<String, usize> = BTreeMap::new();
    for c in &creds {
        *headers
            .entry(String::from_utf8(c.header_bytes().unwrap()).unwrap())
            .or_default() += 1;
    }
    assert_eq!(
        headers,
        BTreeMap::from([
            ("pid-age/v1/BR".to_string(), 3),
            ("pid-age/v1/DE".to_string(), 1),
            ("pid-age/v1/PT".to_string(), 2),
        ])
    );
}

#[test]
fn seeded_keygen_is_reproducible_and_does_not_overwrite() {
    let dir = scratch("keygen");
    assert!(keygen(&dir, &[]).status.success());
    let first: PublicKeyFile = read_json(&dir.join("issuer-0.pub.json")).unwrap();

    let again = keygen(&dir, &[]);
    assert!(
        !again.status.success(),
        "keygen overwrote an existing key without --force"
    );

    assert!(keygen(&dir, &["--force"]).status.success());
    let second: PublicKeyFile = read_json(&dir.join("issuer-0.pub.json")).unwrap();
    assert_eq!(first, second);
}
