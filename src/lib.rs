//! redact — scrub secrets and PII from text before sharing it.
//!
//! The core is a [`Redactor`]: an ordered list of named [`Rule`]s, each a
//! regular expression, applied in turn to the input. A rule may keep a prefix
//! (named group `keep`) and a suffix (named group `tail`) around the redacted
//! value, so `password=hunter2` becomes `password=[REDACTED]` and
//! `https://user:pw@host` becomes `https://[REDACTED]@host`.
//!
//! Redaction is best-effort pattern matching, not a guarantee. It is meant to
//! catch the common shapes of credentials and personal data before a log is
//! pasted into an issue, a chat, or an LLM prompt. Everything runs locally.

use anyhow::{anyhow, Context, Result};
use regex::{Captures, Regex};

/// The default placeholder substituted for a redacted value.
pub const DEFAULT_PLACEHOLDER: &str = "[REDACTED]";

/// A built-in rule definition: a name, its pattern, and whether it is on by
/// default. Patterns may use the named groups `keep` (preserved prefix) and
/// `tail` (preserved suffix); everything else they match is redacted.
pub struct RuleSpec {
    pub name: &'static str,
    pub pattern: &'static str,
    pub default: bool,
}

/// The catalog of built-in rules, in application order (most specific first).
pub fn rule_specs() -> Vec<RuleSpec> {
    vec![
        RuleSpec {
            name: "private-key",
            pattern: r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            default: true,
        },
        RuleSpec {
            name: "jwt",
            pattern: r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            default: true,
        },
        RuleSpec {
            name: "aws-access-key",
            pattern: r"\b(?:AKIA|ASIA|AGPA|AROA|AIDA)[A-Z0-9]{16}\b",
            default: true,
        },
        RuleSpec {
            name: "github-token",
            pattern: r"\bgh[posru]_[A-Za-z0-9]{36,}\b",
            default: true,
        },
        RuleSpec {
            name: "slack-token",
            pattern: r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
            default: true,
        },
        RuleSpec {
            name: "google-api-key",
            pattern: r"\bAIza[0-9A-Za-z_-]{35}\b",
            default: true,
        },
        RuleSpec {
            name: "openai-key",
            pattern: r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
            default: true,
        },
        RuleSpec {
            name: "bearer",
            pattern: r"(?P<keep>(?i:bearer)\s+)[A-Za-z0-9._~+/=-]{8,}",
            default: true,
        },
        RuleSpec {
            name: "url-credential",
            pattern: r"(?P<keep>[a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]*(?P<tail>@)",
            default: true,
        },
        RuleSpec {
            // The `(?:[a-z0-9]+_)*` prefix lets env-var style names like
            // DB_PASSWORD or AWS_SECRET_ACCESS_KEY match (the `_` would
            // otherwise defeat the `\b` before the keyword), without matching
            // words that merely contain a keyword such as COMPASS.
            name: "key-value",
            pattern: r#"(?i)(?P<keep>\b(?:[a-z0-9]+_)*(?:password|passwd|pass|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|token)\b\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s"']+)"#,
            default: true,
        },
        RuleSpec {
            name: "email",
            pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            default: true,
        },
        RuleSpec {
            name: "ipv4",
            pattern: r"\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b",
            default: true,
        },
        RuleSpec {
            name: "ipv6",
            pattern: r"(?i)\b(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}\b",
            default: false,
        },
    ]
}

/// A compiled redaction rule.
pub struct Rule {
    pub name: String,
    regex: Regex,
}

impl Rule {
    /// Compile a rule from a name and a regular-expression pattern.
    pub fn compile(name: impl Into<String>, pattern: &str) -> Result<Rule> {
        let name = name.into();
        let regex =
            Regex::new(pattern).with_context(|| format!("invalid pattern for rule {name:?}"))?;
        Ok(Rule { name, regex })
    }
}

/// How many redactions a single rule made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCount {
    pub name: String,
    pub count: usize,
}

/// The result of redacting text: the scrubbed output and per-rule counts.
#[derive(Debug, Clone)]
pub struct RedactOutcome {
    pub text: String,
    pub counts: Vec<RuleCount>,
}

impl RedactOutcome {
    /// Total number of redactions across all rules.
    pub fn total(&self) -> usize {
        self.counts.iter().map(|c| c.count).sum()
    }
}

/// An ordered set of rules and the placeholder they substitute.
pub struct Redactor {
    rules: Vec<Rule>,
    placeholder: String,
}

impl Redactor {
    /// Build a redactor from explicit rules and a placeholder string.
    pub fn new(rules: Vec<Rule>, placeholder: impl Into<String>) -> Redactor {
        Redactor {
            rules,
            placeholder: placeholder.into(),
        }
    }

    /// Apply every rule, in order, returning the scrubbed text and counts.
    pub fn redact(&self, input: &str) -> RedactOutcome {
        let mut text = input.to_string();
        let mut counts = Vec::new();
        for rule in &self.rules {
            let mut count = 0usize;
            let replaced = rule.regex.replace_all(&text, |caps: &Captures| {
                count += 1;
                let pre = caps.name("keep").map_or("", |m| m.as_str());
                let suf = caps.name("tail").map_or("", |m| m.as_str());
                format!("{pre}{}{suf}", self.placeholder)
            });
            text = replaced.into_owned();
            if count > 0 {
                counts.push(RuleCount {
                    name: rule.name.clone(),
                    count,
                });
            }
        }
        RedactOutcome { text, counts }
    }
}

/// Build a redactor from optional explicit type names plus extra custom
/// patterns. When `types` is `None`, the rules marked default are used.
pub fn build_redactor(
    types: Option<&[String]>,
    extra_patterns: &[String],
    placeholder: impl Into<String>,
) -> Result<Redactor> {
    let specs = rule_specs();
    let mut rules = Vec::new();
    match types {
        Some(names) => {
            for name in names {
                let spec = specs
                    .iter()
                    .find(|s| s.name == name)
                    .ok_or_else(|| anyhow!("unknown type {name:?} (see --list-types)"))?;
                rules.push(Rule::compile(spec.name, spec.pattern)?);
            }
        }
        None => {
            for spec in specs.iter().filter(|s| s.default) {
                rules.push(Rule::compile(spec.name, spec.pattern)?);
            }
        }
    }
    for (i, pattern) in extra_patterns.iter().enumerate() {
        rules.push(Rule::compile(format!("custom{}", i + 1), pattern)?);
    }
    Ok(Redactor::new(rules, placeholder))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact_default(input: &str) -> RedactOutcome {
        build_redactor(None, &[], DEFAULT_PLACEHOLDER)
            .unwrap()
            .redact(input)
    }

    #[test]
    fn redacts_key_value_secrets_keeping_the_label() {
        let out = redact_default("password=hunter2 and api_key: ABC123XYZ");
        assert_eq!(out.text, "password=[REDACTED] and api_key: [REDACTED]");
    }

    #[test]
    fn redacts_env_var_style_keys_but_not_lookalike_words() {
        let out = redact_default("DB_PASSWORD=sup3r and AWS_SECRET_ACCESS_KEY=abc");
        assert_eq!(
            out.text,
            "DB_PASSWORD=[REDACTED] and AWS_SECRET_ACCESS_KEY=[REDACTED]"
        );
        // A word that merely contains a keyword must be left alone.
        assert_eq!(redact_default("COMPASS=north").text, "COMPASS=north");
    }

    #[test]
    fn redacts_url_credentials_keeping_scheme_and_host() {
        let out = redact_default("clone https://alice:s3cret@example.com/repo.git now");
        assert_eq!(
            out.text,
            "clone https://[REDACTED]@example.com/repo.git now"
        );
    }

    #[test]
    fn redacts_bearer_tokens_keeping_the_scheme_word() {
        let out = redact_default("Authorization: Bearer abcDEF123456ghijkl");
        assert_eq!(out.text, "Authorization: Bearer [REDACTED]");
    }

    #[test]
    fn redacts_structured_tokens() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF_-123";
        assert_eq!(redact_default(jwt).text, "[REDACTED]");
        assert_eq!(
            redact_default("key AKIAIOSFODNN7EXAMPLE here").text,
            "key [REDACTED] here"
        );
        assert_eq!(
            redact_default("ghp_0123456789abcdefghijklmnopqrstuvwxyz").text,
            "[REDACTED]"
        );
    }

    #[test]
    fn redacts_pem_private_key_block() {
        let pem = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\nDEF==\n-----END RSA PRIVATE KEY-----\nafter";
        assert_eq!(redact_default(pem).text, "before\n[REDACTED]\nafter");
    }

    #[test]
    fn redacts_email_and_ipv4() {
        let out = redact_default("from a@b.com at 10.0.0.1");
        assert_eq!(out.text, "from [REDACTED] at [REDACTED]");
    }

    #[test]
    fn leaves_benign_text_untouched() {
        let out = redact_default("the quick brown fox jumps at 12:34");
        assert_eq!(out.text, "the quick brown fox jumps at 12:34");
        assert_eq!(out.total(), 0);
    }

    #[test]
    fn reports_per_rule_counts() {
        let out = redact_default("a@b.com c@d.com password=x");
        let emails = out.counts.iter().find(|c| c.name == "email").unwrap();
        assert_eq!(emails.count, 2);
        assert_eq!(out.total(), 3);
    }

    #[test]
    fn type_selection_limits_rules() {
        let types = vec!["email".to_string()];
        let out = build_redactor(Some(&types), &[], DEFAULT_PLACEHOLDER)
            .unwrap()
            .redact("a@b.com password=x");
        // Only email is redacted; the password is left alone.
        assert_eq!(out.text, "[REDACTED] password=x");
    }

    #[test]
    fn custom_pattern_is_applied() {
        let extra = vec![r"\bTOP-SECRET-\d+\b".to_string()];
        let out = build_redactor(None, &extra, DEFAULT_PLACEHOLDER)
            .unwrap()
            .redact("ref TOP-SECRET-42 end");
        assert_eq!(out.text, "ref [REDACTED] end");
    }

    #[test]
    fn unknown_type_is_an_error() {
        let types = vec!["nope".to_string()];
        assert!(build_redactor(Some(&types), &[], DEFAULT_PLACEHOLDER).is_err());
    }
}
