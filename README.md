# redact

> Scrub secrets and PII from logs and text before sharing them. Fast, offline Rust CLI.

[![CI](https://github.com/printemps-tokyo/redact/actions/workflows/ci.yml/badge.svg)](https://github.com/printemps-tokyo/redact/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

`redact` strips API keys, tokens, passwords, private keys, emails, and IP
addresses out of text, so you can paste a log into an issue, a chat, or an LLM
prompt without leaking credentials.

```console
$ cat app.log | redact
user logged in from [REDACTED]
DB_PASSWORD=[REDACTED]
cloning https://[REDACTED]@github.com/acme/app.git
Authorization: Bearer [REDACTED]
```

It reads from stdin or a file, writes the scrubbed text to stdout or a file, and
runs entirely offline. Redaction is best-effort pattern matching, not a
guarantee (see [Limitations](#limitations)).

## Requirements

- A Rust toolchain (to build from source)

## Install

```bash
cargo install --git https://github.com/printemps-tokyo/redact
# or, from a clone:
cargo install --path .
```

Prebuilt binaries will be attached to each [release](https://github.com/printemps-tokyo/redact/releases) once a version is tagged.

## Usage

```bash
redact < app.log                 # scrub stdin -> stdout
redact app.log -o clean.log      # scrub a file to a file
cat err.log | redact | pbcopy    # scrub before pasting somewhere
redact --types email,ipv4 notes.txt    # only some rule types
redact --add-pattern '\bEMP-\d{6}\b' staff.log   # add a custom rule
redact --check ci.log            # scan only: exit 1 if anything is found
redact --stats < app.log > clean.log   # also report counts on stderr
redact --list-types              # show available rules and their defaults
```

| Option | Description |
| --- | --- |
| `[input]` | Input file (default: stdin) |
| `-o, --output <file>` | Output file (default: stdout) |
| `--types <list>` | Comma list of rule names to use instead of the defaults |
| `--add-pattern <regex>` | Add a custom regex rule (repeatable) |
| `--placeholder <text>` | String to substitute (default: `[REDACTED]`) |
| `--stats` | Print per-rule counts to stderr |
| `--check` | Scan only; print findings and exit 1 if any are found |
| `--list-types` | List available rules (and whether each is on by default) |

### Scanning in CI

`--check` makes `redact` a leak detector: it reads the input, reports what it
found on stderr, writes no scrubbed output, and exits `1` when anything matches.

```bash
redact --check build.log || echo "secrets detected in build.log"
```

## What it redacts

On by default: PEM private-key blocks, JWTs, AWS access-key IDs, GitHub /
GitLab / Stripe / npm / SendGrid / Slack / Google / OpenAI key formats,
`Bearer` tokens, credentials embedded in URLs (`scheme://user:pass@host`),
`key: value` secrets (including env-var names like `DB_PASSWORD` and
`AWS_SECRET_ACCESS_KEY`), email addresses, and IPv4 addresses. Stripe keys are
caught in both live and test mode (`sk_live_`, `rk_live_`, `sk_test_`,
`rk_test_`); test keys look identical to live ones and are still credentials.
IPv6 is available but off by default; enable it with `--types`.

A redacted value is replaced by the placeholder while a recognizable label is
kept: `password=hunter2` becomes `password=[REDACTED]`, and
`https://user:pw@host` becomes `https://[REDACTED]@host`.

Run `redact --list-types` for the full list.

## Limitations

Pattern matching cannot recognize every secret, and it can occasionally match
something that is not one. `redact` is a safety net that catches the common
shapes of credentials and personal data; it is not a guarantee. Always review
the output before sharing sensitive logs, and keep real secrets out of logs in
the first place. See [SECURITY.md](./SECURITY.md) to report an issue.

## Programmatic API

```rust
use redact::{build_redactor, DEFAULT_PLACEHOLDER};

let redactor = build_redactor(None, &[], DEFAULT_PLACEHOLDER)?; // default rules
let outcome = redactor.redact("token: ghp_0123456789abcdefghijklmnopqrstuvwxyz");
println!("{}", outcome.text);   // token: [REDACTED]
println!("{}", outcome.total()); // 1
```

## License

[MIT](./LICENSE) (c) printemps.tokyo
