//! The Prover. So far it only checks credentials it has received, which the
//! BBS model has the Prover do before relying on them. Presentation generation
//! comes next.

use anyhow::{Context, Result, bail};
use common::{CredentialRecord, PublicKeyFile, bbs};

/// Checks one credential with the draft's Verify, against the Issuer's public
/// key. The credential must name the same key id and ciphersuite as the key.
pub fn check_credential(public: &PublicKeyFile, credential: &CredentialRecord) -> Result<()> {
    if credential.key_id != public.key_id {
        bail!(
            "credential is under key {:?}, not {:?}",
            credential.key_id,
            public.key_id
        );
    }
    if credential.ciphersuite != public.ciphersuite {
        bail!(
            "credential uses {}, key uses {}",
            credential.ciphersuite,
            public.ciphersuite
        );
    }
    let pk = hex::decode(&public.public_key).context("public key is not valid hex")?;
    bbs::verify(
        public.ciphersuite,
        &pk,
        &credential.header_bytes()?,
        &credential.message_bytes(),
        &credential.signature_bytes()?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{Ciphersuite, IssuerKeyFile, PopulationRecord};
    use issuer::Issuer;
    use issuer::config::IssuerConfig;
    use std::path::Path;

    fn setup() -> (PublicKeyFile, CredentialRecord) {
        let kp = bbs::keygen(Ciphersuite::Bls12381Sha256, &[3u8; 32], None).unwrap();
        let key = IssuerKeyFile {
            key_id: "k0".into(),
            ciphersuite: Ciphersuite::Bls12381Sha256,
            secret_key: hex::encode(kp.secret_key),
            public_key: hex::encode(kp.public_key),
        };
        let config = IssuerConfig::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs/examples/pid-age.toml"),
        )
        .unwrap();
        let record = first_example_record();
        let public = key.public();
        let credential = Issuer::new(config, key)
            .unwrap()
            .issue(&record, false)
            .unwrap();
        (public, credential)
    }

    fn first_example_record() -> PopulationRecord {
        common::read_jsonl::<PopulationRecord>(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/examples/population.jsonl"),
        )
        .unwrap()
        .remove(0)
    }

    #[test]
    fn accepts_valid_credential() {
        let (public, credential) = setup();
        check_credential(&public, &credential).unwrap();
    }

    #[test]
    fn rejects_changed_message() {
        let (public, mut credential) = setup();
        credential.messages[2] = "birth_date=2010-01-01".into();
        assert!(check_credential(&public, &credential).is_err());
    }

    #[test]
    fn rejects_changed_header() {
        let (public, mut credential) = setup();
        credential.header = hex::encode("pid-age/v1/DE");
        assert!(check_credential(&public, &credential).is_err());
    }

    #[test]
    fn rejects_dropped_message() {
        let (public, mut credential) = setup();
        credential.messages.pop();
        assert!(check_credential(&public, &credential).is_err());
    }

    #[test]
    fn rejects_other_key_id() {
        let (mut public, credential) = setup();
        public.key_id = "k1".into();
        assert!(check_credential(&public, &credential).is_err());
    }
}
