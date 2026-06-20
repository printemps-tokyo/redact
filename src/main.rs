//! Command-line entry point for redact.

use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use redact::{build_redactor, rule_specs, DEFAULT_PLACEHOLDER};

/// Scrub secrets and PII from logs and text before sharing them.
#[derive(Parser, Debug)]
#[command(name = "redact", version, about, long_about = None)]
struct Cli {
    /// Input file to read (default: standard input).
    input: Option<PathBuf>,

    /// Write the scrubbed text here (default: standard output).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Comma list of rule names to use instead of the defaults (see --list-types).
    #[arg(long, value_delimiter = ',')]
    types: Option<Vec<String>>,

    /// Add a custom regex rule (repeatable).
    #[arg(long = "add-pattern", value_name = "REGEX")]
    add_pattern: Vec<String>,

    /// String substituted for each redacted value.
    #[arg(long, default_value = DEFAULT_PLACEHOLDER)]
    placeholder: String,

    /// Print per-rule redaction counts to stderr.
    #[arg(long)]
    stats: bool,

    /// Scan only: report findings and exit non-zero if any are found. Implies
    /// no scrubbed output is written.
    #[arg(long)]
    check: bool,

    /// List the available rule names and exit.
    #[arg(long)]
    list_types: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list_types {
        for spec in rule_specs() {
            let mark = if spec.default { "on " } else { "off" };
            println!("{mark}  {}", spec.name);
        }
        return Ok(());
    }

    let input = match &cli.input {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("failed to read stdin")?;
            buf
        }
    };

    let redactor = build_redactor(cli.types.as_deref(), &cli.add_pattern, cli.placeholder)?;
    let outcome = redactor.redact(&input);

    if cli.check {
        // Scanner mode: report to stderr, no scrubbed output, exit code signals
        // whether anything was found.
        for c in &outcome.counts {
            eprintln!("{}: {}", c.name, c.count);
        }
        let total = outcome.total();
        if total > 0 {
            eprintln!("redact: found {total} potential secret(s)");
            std::process::exit(1);
        }
        eprintln!("redact: no secrets found");
        return Ok(());
    }

    match &cli.output {
        Some(path) => std::fs::write(path, &outcome.text)
            .with_context(|| format!("failed to write {}", path.display()))?,
        None => {
            std::io::stdout()
                .write_all(outcome.text.as_bytes())
                .context("failed to write stdout")?;
        }
    }

    if cli.stats {
        for c in &outcome.counts {
            eprintln!("{}: {}", c.name, c.count);
        }
        eprintln!("redact: {} redaction(s)", outcome.total());
    }

    Ok(())
}
