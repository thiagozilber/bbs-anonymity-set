//! Types and encodings shared by the Issuer, Prover and Verifier.
//!
//! Everything that crosses a process boundary (key files, population records,
//! credential records) is defined here, so the three roles cannot drift apart.

pub mod bbs;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Ciphersuites
// ---------------------------------------------------------------------------

/// The two ciphersuites defined by the BBS draft.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ciphersuite {
    #[serde(rename = "BLS12-381-SHA-256")]
    Bls12381Sha256,
    #[serde(rename = "BLS12-381-SHAKE-256")]
    Bls12381Shake256,
}

impl Ciphersuite {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bls12381Sha256 => "BLS12-381-SHA-256",
            Self::Bls12381Shake256 => "BLS12-381-SHAKE-256",
        }
    }
}

impl fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Ciphersuite {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "BLS12-381-SHA-256" => Ok(Self::Bls12381Sha256),
            "BLS12-381-SHAKE-256" => Ok(Self::Bls12381Shake256),
            other => bail!(
                "unknown ciphersuite {other:?} (expected BLS12-381-SHA-256 or BLS12-381-SHAKE-256)"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Key files
// ---------------------------------------------------------------------------

/// An Issuer key pair as written by `issuer keygen`. Contains the secret key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerKeyFile {
    pub key_id: String,
    pub ciphersuite: Ciphersuite,
    /// Hex-encoded secret key (32 octets).
    pub secret_key: String,
    /// Hex-encoded public key (96 octets, compressed G2 point).
    pub public_key: String,
}

impl IssuerKeyFile {
    /// The public half, safe to hand to Provers and Verifiers.
    pub fn public(&self) -> PublicKeyFile {
        PublicKeyFile {
            key_id: self.key_id.clone(),
            ciphersuite: self.ciphersuite,
            public_key: self.public_key.clone(),
        }
    }
}

/// An Issuer public key, as distributed to Provers and Verifiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyFile {
    pub key_id: String,
    pub ciphersuite: Ciphersuite,
    /// Hex-encoded public key (96 octets, compressed G2 point).
    pub public_key: String,
}

// ---------------------------------------------------------------------------
// Population and credential records
// ---------------------------------------------------------------------------

/// One Prover in the input population, as produced by the population generator.
///
/// Attribute values must be JSON scalars. A `null` value is treated the same as
/// an absent attribute.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PopulationRecord {
    pub prover_id: String,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// One issued credential, as written by `issuer issue`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// Ground-truth label. Carried for the analysis; never part of what is signed.
    pub prover_id: String,
    pub key_id: String,
    pub ciphersuite: Ciphersuite,
    /// Hex-encoded BBS `header` the signature is bound to.
    pub header: String,
    /// The signed messages in index order, each encoded by [`encode_message`].
    pub messages: Vec<String>,
    /// Hex-encoded BBS signature (80 octets).
    pub signature: String,
}

impl CredentialRecord {
    pub fn header_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.header).context("credential header is not valid hex")
    }

    pub fn message_bytes(&self) -> Vec<Vec<u8>> {
        self.messages
            .iter()
            .map(|m| m.as_bytes().to_vec())
            .collect()
    }

    pub fn signature_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.signature).context("credential signature is not valid hex")
    }
}

// ---------------------------------------------------------------------------
// Message encoding
// ---------------------------------------------------------------------------

/// Encodes one attribute as a BBS message: the UTF-8 string `<name>=<value>`.
///
/// Messages are self-describing, so a Verifier can interpret a disclosed
/// message without knowing the credential's layout. This matters when optional
/// attributes are omitted, because omission shifts the index of every later
/// attribute.
pub fn encode_message(name: &str, value: &str) -> Result<String> {
    validate_attribute_name(name)?;
    Ok(format!("{name}={value}"))
}

/// Splits a message produced by [`encode_message`] into `(name, value)`.
pub fn decode_message(message: &str) -> Result<(&str, &str)> {
    let (name, value) = message
        .split_once('=')
        .with_context(|| format!("message {message:?} has no '=' separator"))?;
    validate_attribute_name(name)?;
    Ok((name, value))
}

/// Attribute names are lowercase ASCII letters, digits and underscores.
pub fn validate_attribute_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !valid {
        bail!("invalid attribute name {name:?}: use [a-z0-9_]+");
    }
    Ok(())
}

/// Renders a JSON scalar as the attribute value string. `None` means absent.
pub fn scalar_to_string(value: &serde_json::Value) -> Result<Option<String>> {
    use serde_json::Value;
    Ok(match value {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Array(_) | Value::Object(_) => {
            bail!("attribute values must be JSON scalars, got {value}")
        }
    })
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("parsing {}", path.display()))
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Reads a JSON Lines file. Blank lines are skipped.
pub fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let item = serde_json::from_str(&line)
            .with_context(|| format!("{}: line {}", path.display(), i + 1))?;
        out.push(item);
    }
    Ok(out)
}

/// Writes a JSON Lines file, one value per line.
pub fn write_jsonl<'a, T: Serialize + 'a>(
    path: &Path,
    items: impl IntoIterator<Item = &'a T>,
) -> Result<()> {
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for item in items {
        serde_json::to_writer(&mut writer, item)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_round_trip() {
        let m = encode_message("birth_date", "1990-01-31").unwrap();
        assert_eq!(m, "birth_date=1990-01-31");
        assert_eq!(decode_message(&m).unwrap(), ("birth_date", "1990-01-31"));
    }

    #[test]
    fn value_may_contain_separator() {
        let m = encode_message("note", "a=b").unwrap();
        assert_eq!(decode_message(&m).unwrap(), ("note", "a=b"));
    }

    #[test]
    fn rejects_bad_names() {
        assert!(encode_message("Birth Date", "x").is_err());
        assert!(encode_message("", "x").is_err());
        assert!(encode_message("a=b", "x").is_err());
    }

    #[test]
    fn scalars() {
        use serde_json::json;
        assert_eq!(scalar_to_string(&json!("x")).unwrap(), Some("x".into()));
        assert_eq!(scalar_to_string(&json!(true)).unwrap(), Some("true".into()));
        assert_eq!(scalar_to_string(&json!(18)).unwrap(), Some("18".into()));
        assert_eq!(scalar_to_string(&json!(null)).unwrap(), None);
        assert!(scalar_to_string(&json!([1])).is_err());
    }

    #[test]
    fn ciphersuite_names() {
        for cs in [Ciphersuite::Bls12381Sha256, Ciphersuite::Bls12381Shake256] {
            assert_eq!(cs.name().parse::<Ciphersuite>().unwrap(), cs);
            let json = serde_json::to_string(&cs).unwrap();
            assert_eq!(json, format!("\"{}\"", cs.name()));
        }
    }
}
