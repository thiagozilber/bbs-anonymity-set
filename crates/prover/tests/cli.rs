//! End-to-end: issue the example population in-process, then run `prover check`.

use common::{
    Ciphersuite, CredentialRecord, IssuerKeyFile, PopulationRecord, bbs, read_jsonl, write_json,
    write_jsonl,
};
use issuer::Issuer;
use issuer::config::IssuerConfig;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Writes a public key file and the example population's credentials to a
/// scratch directory. Returns (dir, public key path, credentials).
fn issue_examples(name: &str) -> (PathBuf, PathBuf, Vec<CredentialRecord>) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let kp = bbs::keygen(Ciphersuite::Bls12381Sha256, &[9u8; 32], None).unwrap();
    let key = IssuerKeyFile {
        key_id: "issuer-0".into(),
        ciphersuite: Ciphersuite::Bls12381Sha256,
        secret_key: hex::encode(kp.secret_key),
        public_key: hex::encode(kp.public_key),
    };
    let public_path = dir.join("issuer-0.pub.json");
    write_json(&public_path, &key.public()).unwrap();

    let config = IssuerConfig::load(&repo_root().join("configs/examples/pid-age.toml")).unwrap();
    let records: Vec<PopulationRecord> =
        read_jsonl(&repo_root().join("data/examples/population.jsonl")).unwrap();
    let credentials = Issuer::new(config, key)
        .unwrap()
        .issue_all(&records, false)
        .unwrap();
    (dir, public_path, credentials)
}

fn check(public: &Path, credentials: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_prover"))
        .arg("check")
        .arg("--public-key")
        .arg(public)
        .arg("--credentials")
        .arg(credentials)
        .output()
        .unwrap()
}

#[test]
fn accepts_issued_credentials() {
    let (dir, public, credentials) = issue_examples("valid");
    let path = dir.join("credentials.jsonl");
    write_jsonl(&path, &credentials).unwrap();

    let out = check(&public, &path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("6 valid, 0 invalid"), "{stderr}");
}

#[test]
fn reports_each_tampered_credential_and_fails() {
    let (dir, public, mut credentials) = issue_examples("tampered");
    credentials[1].messages[3] = "age_over_18=true".into(); // p0002 is under 18
    credentials[4].header = hex::encode("pid-age/v1/BR"); // p0005 was issued under DE
    let path = dir.join("credentials.jsonl");
    write_jsonl(&path, &credentials).unwrap();

    let out = check(&public, &path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("4 valid, 2 invalid"), "{stderr}");
    assert!(
        stderr.contains("p0002") && stderr.contains("p0005"),
        "{stderr}"
    );
}
