use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use common::{CredentialRecord, PublicKeyFile, read_json, read_jsonl};
use std::path::PathBuf;

/// BBS Prover for the anonymity-set measurement.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify issued credentials against the Issuer's public key. Exits
    /// non-zero if any credential fails.
    Check {
        /// Public key file from `issuer keygen`.
        #[arg(long)]
        public_key: PathBuf,
        /// Credentials from `issuer issue`, one JSON record per line.
        #[arg(long)]
        credentials: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Check {
            public_key,
            credentials,
        } => check(public_key, credentials),
    }
}

fn check(public_key: PathBuf, credentials: PathBuf) -> Result<()> {
    let public: PublicKeyFile = read_json(&public_key)?;
    let records: Vec<CredentialRecord> = read_jsonl(&credentials)?;
    let mut failed = 0;
    for c in &records {
        if let Err(e) = prover::check_credential(&public, c) {
            failed += 1;
            eprintln!("  invalid  {}: {e:#}", c.prover_id);
        }
    }
    let total = records.len();
    eprintln!(
        "checked {total} credentials against key {:?}: {} valid, {failed} invalid",
        public.key_id,
        total - failed
    );
    if failed > 0 {
        bail!("{failed} of {total} credentials failed verification");
    }
    Ok(())
}
