//! Header templates: `pid-age/v1/{issuing_country}` and similar.

use anyhow::{Result, bail};
use common::{PopulationRecord, scalar_to_string, validate_attribute_name};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    Attribute(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderTemplate {
    parts: Vec<Part>,
}

impl HeaderTemplate {
    pub fn parse(template: &str) -> Result<Self> {
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut chars = template.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '{' if chars.peek() == Some(&'{') => {
                    chars.next();
                    literal.push('{');
                }
                '}' if chars.peek() == Some(&'}') => {
                    chars.next();
                    literal.push('}');
                }
                '{' => {
                    let mut name = String::new();
                    loop {
                        match chars.next() {
                            Some('}') => break,
                            Some(ch) => name.push(ch),
                            None => bail!("header template {template:?}: unclosed '{{'"),
                        }
                    }
                    validate_attribute_name(&name)?;
                    if !literal.is_empty() {
                        parts.push(Part::Literal(std::mem::take(&mut literal)));
                    }
                    parts.push(Part::Attribute(name));
                }
                '}' => bail!(
                    "header template {template:?}: unmatched '}}' (write '}}}}' for a literal)"
                ),
                other => literal.push(other),
            }
        }
        if !literal.is_empty() {
            parts.push(Part::Literal(literal));
        }
        Ok(Self { parts })
    }

    /// Attribute names the template reads.
    pub fn attributes(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().filter_map(|p| match p {
            Part::Attribute(name) => Some(name.as_str()),
            Part::Literal(_) => None,
        })
    }

    pub fn render(&self, record: &PopulationRecord) -> Result<String> {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                Part::Literal(s) => out.push_str(s),
                Part::Attribute(name) => {
                    let value = match record.attributes.get(name) {
                        Some(v) => scalar_to_string(v)?,
                        None => None,
                    };
                    match value {
                        Some(v) => out.push_str(&v),
                        None => bail!(
                            "prover {}: header template needs attribute {name:?}, which is absent",
                            record.prover_id
                        ),
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(attrs: serde_json::Value) -> PopulationRecord {
        serde_json::from_value(json!({ "prover_id": "p1", "attributes": attrs })).unwrap()
    }

    #[test]
    fn renders_placeholders() {
        let t = HeaderTemplate::parse("pid-age/v1/{issuing_country}").unwrap();
        let r = record(json!({ "issuing_country": "BR" }));
        assert_eq!(t.render(&r).unwrap(), "pid-age/v1/BR");
        assert_eq!(t.attributes().collect::<Vec<_>>(), ["issuing_country"]);
    }

    #[test]
    fn constant_template() {
        let t = HeaderTemplate::parse("pid-age/v1").unwrap();
        assert_eq!(t.render(&record(json!({}))).unwrap(), "pid-age/v1");
        assert_eq!(t.attributes().count(), 0);
    }

    #[test]
    fn literal_braces() {
        let t = HeaderTemplate::parse("{{x}}/{a}").unwrap();
        assert_eq!(t.render(&record(json!({ "a": 1 }))).unwrap(), "{x}/1");
    }

    #[test]
    fn errors() {
        assert!(HeaderTemplate::parse("{unclosed").is_err());
        assert!(HeaderTemplate::parse("stray}").is_err());
        assert!(HeaderTemplate::parse("{Bad Name}").is_err());
        let t = HeaderTemplate::parse("{a}").unwrap();
        assert!(t.render(&record(json!({}))).is_err());
        assert!(t.render(&record(json!({ "a": null }))).is_err());
    }
}
