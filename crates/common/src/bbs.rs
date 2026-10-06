//! Thin wrapper over ZKryptium's BBS implementation.
//!
//! All BBS operations used by the Issuer, Prover and Verifier go through this
//! module, so the library is called in exactly one way across the project and
//! the ciphersuite is chosen at runtime from the key file.
//!
//! Sign is deterministic in the draft: the same key, header and messages always
//! produce the same signature.

use crate::Ciphersuite;
use anyhow::{Result, anyhow, bail};
use elliptic_curve::hash2curve::ExpandMsg;
use zkryptium::bbsplus::ciphersuites::{BbsCiphersuite, Bls12381Sha256, Bls12381Shake256};
use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BBSplus;
use zkryptium::schemes::generics::Signature;

/// Secret key length in octets.
pub const SECRET_KEY_LEN: usize = 32;
/// Public key length in octets (compressed G2 point).
pub const PUBLIC_KEY_LEN: usize = 96;
/// Signature length in octets (compressed G1 point plus one scalar).
pub const SIGNATURE_LEN: usize = 80;
/// Minimum `key_material` length required by the draft's KeyGen.
pub const MIN_KEY_MATERIAL_LEN: usize = 32;

/// A key pair as raw octets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPairBytes {
    pub secret_key: [u8; SECRET_KEY_LEN],
    pub public_key: [u8; PUBLIC_KEY_LEN],
}

/// The draft's KeyGen. `key_dst` is left at the ciphersuite default.
pub fn keygen(
    cs: Ciphersuite,
    key_material: &[u8],
    key_info: Option<&[u8]>,
) -> Result<KeyPairBytes> {
    if key_material.len() < MIN_KEY_MATERIAL_LEN {
        bail!(
            "key_material must be at least {MIN_KEY_MATERIAL_LEN} octets, got {}",
            key_material.len()
        );
    }
    match cs {
        Ciphersuite::Bls12381Sha256 => keygen_with::<Bls12381Sha256>(key_material, key_info),
        Ciphersuite::Bls12381Shake256 => keygen_with::<Bls12381Shake256>(key_material, key_info),
    }
}

/// The draft's Sign.
pub fn sign(
    cs: Ciphersuite,
    secret_key: &[u8],
    public_key: &[u8],
    header: &[u8],
    messages: &[Vec<u8>],
) -> Result<[u8; SIGNATURE_LEN]> {
    let sk = BBSplusSecretKey::from_bytes(secret_key).map_err(lib_err)?;
    let pk = BBSplusPublicKey::from_bytes(public_key).map_err(lib_err)?;
    match cs {
        Ciphersuite::Bls12381Sha256 => sign_with::<Bls12381Sha256>(&sk, &pk, header, messages),
        Ciphersuite::Bls12381Shake256 => sign_with::<Bls12381Shake256>(&sk, &pk, header, messages),
    }
}

/// The draft's Verify. Returns `Ok(())` for a valid signature.
pub fn verify(
    cs: Ciphersuite,
    public_key: &[u8],
    header: &[u8],
    messages: &[Vec<u8>],
    signature: &[u8],
) -> Result<()> {
    let pk = BBSplusPublicKey::from_bytes(public_key).map_err(lib_err)?;
    let sig: &[u8; SIGNATURE_LEN] = signature.try_into().map_err(|_| {
        anyhow!(
            "signature must be {SIGNATURE_LEN} octets, got {}",
            signature.len()
        )
    })?;
    match cs {
        Ciphersuite::Bls12381Sha256 => verify_with::<Bls12381Sha256>(&pk, header, messages, sig),
        Ciphersuite::Bls12381Shake256 => {
            verify_with::<Bls12381Shake256>(&pk, header, messages, sig)
        }
    }
}

fn keygen_with<CS>(key_material: &[u8], key_info: Option<&[u8]>) -> Result<KeyPairBytes>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let kp = KeyPair::<BBSplus<CS>>::generate(key_material, key_info, None).map_err(lib_err)?;
    Ok(KeyPairBytes {
        secret_key: kp.private_key().to_bytes(),
        public_key: kp.public_key().to_bytes(),
    })
}

fn sign_with<CS>(
    sk: &BBSplusSecretKey,
    pk: &BBSplusPublicKey,
    header: &[u8],
    messages: &[Vec<u8>],
) -> Result<[u8; SIGNATURE_LEN]>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let sig =
        Signature::<BBSplus<CS>>::sign(Some(messages), sk, pk, Some(header)).map_err(lib_err)?;
    Ok(sig.to_bytes())
}

fn verify_with<CS>(
    pk: &BBSplusPublicKey,
    header: &[u8],
    messages: &[Vec<u8>],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let sig = Signature::<BBSplus<CS>>::from_bytes(signature).map_err(lib_err)?;
    sig.verify(pk, Some(messages), Some(header))
        .map_err(lib_err)
}

fn lib_err(e: zkryptium::errors::Error) -> anyhow::Error {
    anyhow!("zkryptium: {e}")
}

#[cfg(test)]
mod tests {
    //! Known-answer tests against the draft's BLS12-381-SHA-256 fixtures, as
    //! shipped in ZKryptium's `fixture_data`. They check that this wrapper calls
    //! the library the way the draft specifies, not the library itself.
    use super::*;

    const KEY_MATERIAL: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    const KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";
    const SK: &str = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc";
    const PK: &str = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c";
    const HEADER: &str = "11223344556677889900aabbccddeeff";
    const MSG: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    const SIG: &str = "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0";

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn keygen_matches_fixture() {
        let kp = keygen(
            Ciphersuite::Bls12381Sha256,
            &h(KEY_MATERIAL),
            Some(&h(KEY_INFO)),
        )
        .unwrap();
        assert_eq!(hex::encode(kp.secret_key), SK);
        assert_eq!(hex::encode(kp.public_key), PK);
    }

    #[test]
    fn sign_matches_fixture() {
        let sig = sign(
            Ciphersuite::Bls12381Sha256,
            &h(SK),
            &h(PK),
            &h(HEADER),
            &[h(MSG)],
        )
        .unwrap();
        assert_eq!(hex::encode(sig), SIG);
        verify(
            Ciphersuite::Bls12381Sha256,
            &h(PK),
            &h(HEADER),
            &[h(MSG)],
            &sig,
        )
        .unwrap();
    }

    #[test]
    fn verify_rejects_changed_header() {
        let sig = h(SIG);
        assert!(
            verify(
                Ciphersuite::Bls12381Sha256,
                &h(PK),
                b"other",
                &[h(MSG)],
                &sig
            )
            .is_err()
        );
    }

    #[test]
    fn keygen_rejects_short_material() {
        assert!(keygen(Ciphersuite::Bls12381Sha256, &[0u8; 31], None).is_err());
    }

    #[test]
    fn shake_round_trip() {
        let kp = keygen(Ciphersuite::Bls12381Shake256, &[7u8; 32], None).unwrap();
        let msgs = vec![b"a=1".to_vec(), b"b=2".to_vec()];
        let sig = sign(
            Ciphersuite::Bls12381Shake256,
            &kp.secret_key,
            &kp.public_key,
            b"h",
            &msgs,
        )
        .unwrap();
        verify(
            Ciphersuite::Bls12381Shake256,
            &kp.public_key,
            b"h",
            &msgs,
            &sig,
        )
        .unwrap();
    }
}
