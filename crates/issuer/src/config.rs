//! Issuer deployment policy, read from a TOML file.
//!
//! Everything a sweep varies on the Issuer side lives here, so each point in a
//! sweep is one config file.

use anyhow::{Context, Result, bail};
use common::validate_attribute_name;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    pub header: HeaderConfig,
    pub schema: SchemaConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderConfig {
    /// Template for the BBS header, rendered per credential and encoded as
    /// UTF-8. `{name}` is replaced by the Prover's value for attribute `name`;
    /// `{{` and `}}` are literal braces. A template without placeholders gives
    /// every credential the same header.
    pub template: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaConfig {
    /// What to do when a Prover lacks an optional attribute. Required, because
    /// it decides whether the message count varies across the population.
    pub absent_optional: AbsentOptional,
    /// Attributes in message-index order.
    pub fields: Vec<FieldConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbsentOptional {
    /// Leave the attribute out. The message count shrinks, and every later
    /// attribute moves down one index.
    Omit,
    /// Sign the message `<name>=` (empty value) in its slot. The message count
    /// and indexes stay fixed across the population.
    Pad,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldConfig {
    pub name: String,
    #[serde(default)]
    pub optional: bool,
}

impl IssuerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema.fields.is_empty() {
            bail!("schema.fields is empty");
        }
        let mut seen = HashSet::new();
        for field in &self.schema.fields {
            validate_attribute_name(&field.name)?;
            if !seen.insert(field.name.as_str()) {
                bail!("schema field {:?} is listed twice", field.name);
            }
        }
        crate::header::HeaderTemplate::parse(&self.header.template)?;
        Ok(())
    }
}
