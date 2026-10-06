//! The Issuer: maps population records to BBS message arrays and headers under
//! a deployment policy, and signs them.

pub mod config;
pub mod header;

use anyhow::{Context, Result, bail};
use common::{
    CredentialRecord, IssuerKeyFile, PopulationRecord, bbs, encode_message, scalar_to_string,
};
use config::{AbsentOptional, IssuerConfig};
use header::HeaderTemplate;
use std::collections::{BTreeMap, HashSet};

pub struct Issuer {
    config: IssuerConfig,
    template: HeaderTemplate,
    key: IssuerKeyFile,
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    /// Attributes a record may carry: schema fields plus header placeholders.
    known_attributes: HashSet<String>,
}

impl Issuer {
    pub fn new(config: IssuerConfig, key: IssuerKeyFile) -> Result<Self> {
        config.validate()?;
        let template = HeaderTemplate::parse(&config.header.template)?;
        let secret_key = hex::decode(&key.secret_key).context("key file: secret_key is not hex")?;
        let public_key = hex::decode(&key.public_key).context("key file: public_key is not hex")?;
        let known_attributes = config
            .schema
            .fields
            .iter()
            .map(|f| f.name.clone())
            .chain(template.attributes().map(str::to_owned))
            .collect();
        Ok(Self {
            config,
            template,
            key,
            secret_key,
            public_key,
            known_attributes,
        })
    }

    /// The ordered message array for one Prover, before signing.
    pub fn messages_for(&self, record: &PopulationRecord) -> Result<Vec<String>> {
        for (name, value) in &record.attributes {
            if !value.is_null() && !self.known_attributes.contains(name) {
                bail!(
                    "prover {}: attribute {name:?} is not in the schema or the header template",
                    record.prover_id
                );
            }
        }
        let mut messages = Vec::with_capacity(self.config.schema.fields.len());
        for field in &self.config.schema.fields {
            let value = match record.attributes.get(&field.name) {
                Some(v) => scalar_to_string(v).with_context(|| {
                    format!("prover {}, attribute {:?}", record.prover_id, field.name)
                })?,
                None => None,
            };
            match (value, field.optional, self.config.schema.absent_optional) {
                (Some(v), _, _) => messages.push(encode_message(&field.name, &v)?),
                (None, false, _) => bail!(
                    "prover {}: required attribute {:?} is absent",
                    record.prover_id,
                    field.name
                ),
                (None, true, AbsentOptional::Omit) => {}
                (None, true, AbsentOptional::Pad) => {
                    messages.push(encode_message(&field.name, "")?)
                }
            }
        }
        Ok(messages)
    }

    /// The rendered header for one Prover, before encoding.
    pub fn header_for(&self, record: &PopulationRecord) -> Result<String> {
        self.template.render(record)
    }

    /// Issues one credential. With `verify`, the signature is checked with the
    /// draft's Verify before it is returned.
    pub fn issue(&self, record: &PopulationRecord, verify: bool) -> Result<CredentialRecord> {
        let messages = self.messages_for(record)?;
        let header = self.header_for(record)?;
        let message_bytes: Vec<Vec<u8>> = messages.iter().map(|m| m.as_bytes().to_vec()).collect();
        let signature = bbs::sign(
            self.key.ciphersuite,
            &self.secret_key,
            &self.public_key,
            header.as_bytes(),
            &message_bytes,
        )
        .with_context(|| format!("signing for prover {}", record.prover_id))?;
        if verify {
            bbs::verify(
                self.key.ciphersuite,
                &self.public_key,
                header.as_bytes(),
                &message_bytes,
                &signature,
            )
            .with_context(|| {
                format!(
                    "verifying the credential just issued to prover {}",
                    record.prover_id
                )
            })?;
        }
        Ok(CredentialRecord {
            prover_id: record.prover_id.clone(),
            key_id: self.key.key_id.clone(),
            ciphersuite: self.key.ciphersuite,
            header: hex::encode(header.as_bytes()),
            messages,
            signature: hex::encode(signature),
        })
    }

    /// Issues a credential to every record. Prover ids must be unique.
    pub fn issue_all(
        &self,
        records: &[PopulationRecord],
        verify: bool,
    ) -> Result<Vec<CredentialRecord>> {
        let mut ids = HashSet::new();
        for r in records {
            if !ids.insert(r.prover_id.as_str()) {
                bail!(
                    "prover id {:?} appears more than once in the population",
                    r.prover_id
                );
            }
        }
        records.iter().map(|r| self.issue(r, verify)).collect()
    }
}

/// Counts used for the end-of-run summary. These are sanity checks on the
/// issued population, not the analysis.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct IssuanceSummary {
    pub credentials: usize,
    /// Credentials per distinct header value.
    pub per_header: BTreeMap<String, usize>,
    /// Credentials per message count L.
    pub per_message_count: BTreeMap<usize, usize>,
}

impl IssuanceSummary {
    pub fn of(credentials: &[CredentialRecord]) -> Result<Self> {
        let mut s = Self {
            credentials: credentials.len(),
            ..Self::default()
        };
        for c in credentials {
            let header = String::from_utf8(c.header_bytes()?).unwrap_or_else(|_| c.header.clone());
            *s.per_header.entry(header).or_default() += 1;
            *s.per_message_count.entry(c.messages.len()).or_default() += 1;
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::Ciphersuite;
    use serde_json::json;

    fn config(absent: &str, template: &str) -> IssuerConfig {
        toml::from_str(&format!(
            r#"
            [header]
            template = "{template}"
            [schema]
            absent_optional = "{absent}"
            [[schema.fields]]
            name = "birth_date"
            [[schema.fields]]
            name = "resident_city"
            optional = true
            [[schema.fields]]
            name = "issuing_country"
            "#
        ))
        .unwrap()
    }

    fn key() -> IssuerKeyFile {
        let kp = bbs::keygen(Ciphersuite::Bls12381Sha256, &[1u8; 32], None).unwrap();
        IssuerKeyFile {
            key_id: "test".into(),
            ciphersuite: Ciphersuite::Bls12381Sha256,
            secret_key: hex::encode(kp.secret_key),
            public_key: hex::encode(kp.public_key),
        }
    }

    fn record(id: &str, attrs: serde_json::Value) -> PopulationRecord {
        serde_json::from_value(json!({ "prover_id": id, "attributes": attrs })).unwrap()
    }

    #[test]
    fn omit_shrinks_message_array() {
        let issuer = Issuer::new(config("omit", "h"), key()).unwrap();
        let full = record(
            "a",
            json!({ "birth_date": "1990-01-01", "resident_city": "POA", "issuing_country": "BR" }),
        );
        let partial = record(
            "b",
            json!({ "birth_date": "1990-01-01", "issuing_country": "BR" }),
        );
        assert_eq!(issuer.messages_for(&full).unwrap().len(), 3);
        assert_eq!(
            issuer.messages_for(&partial).unwrap(),
            ["birth_date=1990-01-01", "issuing_country=BR"]
        );
    }

    #[test]
    fn pad_keeps_message_array_fixed() {
        let issuer = Issuer::new(config("pad", "h"), key()).unwrap();
        let partial = record(
            "b",
            json!({ "birth_date": "1990-01-01", "issuing_country": "BR" }),
        );
        assert_eq!(
            issuer.messages_for(&partial).unwrap(),
            [
                "birth_date=1990-01-01",
                "resident_city=",
                "issuing_country=BR"
            ]
        );
    }

    #[test]
    fn rejects_missing_required_and_unknown_attributes() {
        let issuer = Issuer::new(config("omit", "h"), key()).unwrap();
        assert!(
            issuer
                .messages_for(&record("a", json!({ "birth_date": "x" })))
                .is_err()
        );
        let extra = record(
            "a",
            json!({ "birth_date": "x", "issuing_country": "BR", "shoe_size": 42 }),
        );
        assert!(issuer.messages_for(&extra).is_err());
    }

    #[test]
    fn header_attribute_need_not_be_signed() {
        let issuer = Issuer::new(config("omit", "pid/{region}"), key()).unwrap();
        let r = record(
            "a",
            json!({ "birth_date": "x", "issuing_country": "BR", "region": "south" }),
        );
        assert_eq!(issuer.header_for(&r).unwrap(), "pid/south");
        assert_eq!(issuer.messages_for(&r).unwrap().len(), 2);
    }

    #[test]
    fn issued_credentials_verify_and_are_deterministic() {
        let issuer = Issuer::new(config("omit", "pid/{issuing_country}"), key()).unwrap();
        let r = record(
            "a",
            json!({ "birth_date": "1990-01-01", "issuing_country": "BR" }),
        );
        let c1 = issuer.issue(&r, true).unwrap();
        let c2 = issuer.issue(&r, true).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(c1.header, hex::encode("pid/BR"));
        bbs::verify(
            c1.ciphersuite,
            &hex::decode(&issuer.key.public_key).unwrap(),
            &c1.header_bytes().unwrap(),
            &c1.message_bytes(),
            &c1.signature_bytes().unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_duplicate_prover_ids() {
        let issuer = Issuer::new(config("omit", "h"), key()).unwrap();
        let r = record("a", json!({ "birth_date": "x", "issuing_country": "BR" }));
        assert!(issuer.issue_all(&[r.clone(), r], false).is_err());
    }
}
