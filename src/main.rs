//! Command-line entry point for redact.

use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use redact::{build_redactor, rule_specs, TokenMap, DEFAULT_PLACEHOLDER};

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
    #[arg(long, default_value = DEFAULT_PLACEHOLDER, conflicts_with = "map")]
    placeholder: String,

    /// Reversible masking: give each distinct value a numbered token such as
    /// [EMAIL_1], and keep token -> value in FILE (JSON, owner-only). An
    /// existing FILE is extended, so the same value keeps its token across
    /// runs. Keep FILE private: it holds every redacted value.
    #[arg(long, value_name = "FILE")]
    map: Option<PathBuf>,

    /// Put the values from --map FILE back in place of their tokens (for
    /// text that went out masked and came back, such as an LLM's answer).
    #[arg(long, requires = "map", conflicts_with_all = ["check", "types", "add_pattern", "stats"])]
    restore: bool,

    /// Print per-rule redaction counts to stderr.
    #[arg(long)]
    stats: bool,

    /// Scan only: report findings and exit non-zero if any are found. Implies
    /// no scrubbed output is written.
    #[arg(long, conflicts_with = "map")]
    check: bool,

    /// With --check, print only the summary, not the per-finding lines.
    #[arg(long, requires = "check")]
    quiet: bool,

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

    if cli.restore {
        let path = cli.map.as_ref().expect("clap requires --map");
        let map = TokenMap::from_json(
            &std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?,
        )
        .with_context(|| format!("{} is not a redact map", path.display()))?;
        let (text, count) = map.restore(&input);
        write_output(cli.output.as_ref(), &text)?;
        eprintln!("redact: restored {count} value(s)");
        return Ok(());
    }

    let redactor = build_redactor(cli.types.as_deref(), &cli.add_pattern, cli.placeholder)?;

    if cli.check {
        // Scanner mode: report each finding to stderr as <file>:<line>: <rule>
        // (never the matched value itself), then the per-rule counts; no
        // scrubbed output is written and the exit code signals whether
        // anything was found.
        let outcome = redactor.check(&input);
        let source = cli
            .input
            .as_ref()
            .map_or_else(|| "-".to_string(), |p| p.display().to_string());
        if !cli.quiet {
            for f in &outcome.findings {
                eprintln!("{source}:{}: {}", f.line, f.rule);
            }
        }
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

    let outcome = match &cli.map {
        Some(path) => {
            let mut map = match std::fs::read_to_string(path) {
                Ok(text) => TokenMap::from_json(&text).with_context(|| {
                    format!("{} exists and is not a redact map", path.display())
                })?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => TokenMap::default(),
                Err(e) => {
                    return Err(e).with_context(|| format!("failed to read {}", path.display()))
                }
            };
            let outcome = redactor.redact_mapped(&input, &mut map);
            // The map first: scrubbed text without its map cannot be restored.
            write_private(path, &map.to_json())?;
            outcome
        }
        None => redactor.redact(&input),
    };
    write_output(cli.output.as_ref(), &outcome.text)?;

    if cli.stats {
        for c in &outcome.counts {
            eprintln!("{}: {}", c.name, c.count);
        }
        eprintln!("redact: {} redaction(s)", outcome.total());
    }

    Ok(())
}

fn write_output(path: Option<&PathBuf>, text: &str) -> Result<()> {
    match path {
        Some(path) => std::fs::write(path, text)
            .with_context(|| format!("failed to write {}", path.display())),
        None => std::io::stdout()
            .write_all(text.as_bytes())
            .context("failed to write stdout"),
    }
}

/// Write `content` through a new owner-only (0600) file renamed over `path`,
/// so the values in a map are never readable by others, even for a moment.
fn write_private(path: &PathBuf, content: &str) -> Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    for n in 0..100 {
        let tmp = dir.join(format!(".{name}.{}.{n}.tmp", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = match opts.open(&tmp) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("failed to write {}", path.display())),
        };
        let result = f
            .write_all(content.as_bytes())
            .and_then(|_| f.sync_all())
            .and_then(|_| std::fs::rename(&tmp, path));
        if let Err(e) = result {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("failed to write {}", path.display()));
        }
        return Ok(());
    }
    anyhow::bail!("failed to write {}: no free temporary name", path.display())
}
