use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use common::{
    Ciphersuite, IssuerKeyFile, PopulationRecord, bbs, read_json, read_jsonl, write_json,
    write_json_private, write_jsonl,
};
use issuer::config::IssuerConfig;
use issuer::{IssuanceSummary, Issuer};
use rand::RngCore;
use std::path::PathBuf;

/// BBS Issuer for the anonymity-set measurement.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Issuer key pair. Writes <key-id>.key.json (secret) and
    /// <key-id>.pub.json (public) to --out-dir.
    Keygen {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long, default_value = "BLS12-381-SHA-256")]
        ciphersuite: Ciphersuite,
        /// Hex key_material (at least 32 octets) for a reproducible key.
        /// Omit for a random key.
        #[arg(long)]
        seed: Option<String>,
        /// key_info passed to KeyGen, as a UTF-8 string.
        #[arg(long)]
        key_info: Option<String>,
        /// Overwrite existing key files.
        #[arg(long)]
        force: bool,
    },
    /// Issue one credential per record in a population file.
    Issue {
        /// Deployment policy (TOML).
        #[arg(long)]
        config: PathBuf,
        /// Secret key file from `keygen`.
        #[arg(long)]
        key: PathBuf,
        /// Population, one JSON record per line.
        #[arg(long)]
        population: PathBuf,
        /// Output credentials, one JSON record per line.
        #[arg(long)]
        out: PathBuf,
        /// Skip verifying each signature after signing.
        #[arg(long)]
        no_verify: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            key_id,
            out_dir,
            ciphersuite,
            seed,
            key_info,
            force,
        } => keygen(key_id, out_dir, ciphersuite, seed, key_info, force),
        Command::Issue {
            config,
            key,
            population,
            out,
            no_verify,
        } => issue(config, key, population, out, !no_verify),
    }
}

fn keygen(
    key_id: String,
    out_dir: PathBuf,
    ciphersuite: Ciphersuite,
    seed: Option<String>,
    key_info: Option<String>,
    force: bool,
) -> Result<()> {
    if key_id.is_empty()
        || !key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("key id {key_id:?} must be non-empty and use [A-Za-z0-9_-]");
    }
    let key_material = match seed {
        Some(hex_seed) => hex::decode(hex_seed.trim()).context("--seed is not valid hex")?,
        None => {
            let mut buf = vec![0u8; bbs::MIN_KEY_MATERIAL_LEN];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            buf
        }
    };
    let kp = bbs::keygen(
        ciphersuite,
        &key_material,
        key_info.as_deref().map(str::as_bytes),
    )?;
    let key_file = IssuerKeyFile {
        key_id: key_id.clone(),
        ciphersuite,
        secret_key: hex::encode(kp.secret_key),
        public_key: hex::encode(kp.public_key),
    };

    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let secret_path = out_dir.join(format!("{key_id}.key.json"));
    let public_path = out_dir.join(format!("{key_id}.pub.json"));
    for path in [&secret_path, &public_path] {
        if path.exists() && !force {
            bail!("{} exists; pass --force to overwrite", path.display());
        }
    }
    write_json_private(&secret_path, &key_file)?;
    write_json(&public_path, &key_file.public())?;
    eprintln!(
        "wrote {} and {}",
        secret_path.display(),
        public_path.display()
    );
    Ok(())
}

fn issue(
    config: PathBuf,
    key: PathBuf,
    population: PathBuf,
    out: PathBuf,
    verify: bool,
) -> Result<()> {
    let config = IssuerConfig::load(&config)?;
    let key: IssuerKeyFile = read_json(&key)?;
    let records: Vec<PopulationRecord> = read_jsonl(&population)?;
    let issuer = Issuer::new(config, key)?;
    let credentials = issuer.issue_all(&records, verify)?;
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    write_jsonl(&out, &credentials)?;

    let summary = IssuanceSummary::of(&credentials)?;
    eprintln!(
        "issued {} credentials to {}{}",
        summary.credentials,
        out.display(),
        if verify {
            " (all signatures verified)"
        } else {
            ""
        }
    );
    eprintln!("  header values: {}", summary.per_header.len());
    for (header, n) in &summary.per_header {
        eprintln!("    {n:>8}  {header}");
    }
    eprintln!("  message counts (L):");
    for (l, n) in &summary.per_message_count {
        eprintln!("    {n:>8}  L = {l}");
    }
    Ok(())
}
