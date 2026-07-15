//! Integration tests for `--check` reporting: <file>:<line>: <rule-name>
//! per finding on stderr, without ever printing the matched value.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_redact"))
}

/// Write test input to a unique temp file and return its path.
fn write_input(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "redact-check-{}-{}-{name}.log",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace(':', "_")
    ));
    std::fs::write(&path, contents).unwrap();
    path
}

fn run_check(path: &PathBuf, extra: &[&str]) -> Output {
    bin()
        .arg("--check")
        .args(extra)
        .arg(path)
        .output()
        .expect("failed to run redact")
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

#[test]
fn check_reports_correct_line_numbers_across_lines() {
    let path = write_input(
        "lines",
        "clean line\ncontact a@b.com\nstill clean\nkey AKIAIOSFODNN7EXAMPLE here\n",
    );
    let out = run_check(&path, &[]);
    let err = stderr_of(&out);
    let p = path.display();
    assert_eq!(out.status.code(), Some(1));
    assert!(err.contains(&format!("{p}:2: email")), "stderr was:\n{err}");
    assert!(
        err.contains(&format!("{p}:4: aws-access-key")),
        "stderr was:\n{err}"
    );
    // Summary and total are still printed.
    assert!(err.contains("redact: found 2 potential secret(s)"));
    std::fs::remove_file(&path).ok();
}

#[test]
fn check_reports_one_line_per_rule_when_two_rules_hit_the_same_line() {
    let path = write_input("tworules", "from a@b.com at 10.0.0.1\n");
    let out = run_check(&path, &[]);
    let err = stderr_of(&out);
    let p = path.display();
    assert_eq!(out.status.code(), Some(1));
    assert!(err.contains(&format!("{p}:1: email")), "stderr was:\n{err}");
    assert!(err.contains(&format!("{p}:1: ipv4")), "stderr was:\n{err}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn check_reports_private_key_block_at_its_start_line() {
    let path = write_input(
        "pem",
        "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIabcFAKEKEYBODY\nDEF==\n-----END RSA PRIVATE KEY-----\nafter a@b.com\n",
    );
    let out = run_check(&path, &[]);
    let err = stderr_of(&out);
    let p = path.display();
    assert_eq!(out.status.code(), Some(1));
    // The multi-line block is reported where it starts.
    assert!(
        err.contains(&format!("{p}:2: private-key")),
        "stderr was:\n{err}"
    );
    // Later findings keep their original line numbers.
    assert!(err.contains(&format!("{p}:6: email")), "stderr was:\n{err}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn check_on_stdin_reports_the_file_as_dash() {
    let mut child = bin()
        .arg("--check")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn redact");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"password=hunter2\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let err = stderr_of(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(err.contains("-:1: key-value"), "stderr was:\n{err}");
}

#[test]
fn check_output_never_contains_the_secret_bytes() {
    let secrets = [
        "leak-me@example.com",
        "AKIAIOSFODNN7EXAMPLE",
        "sup3r-s3cret-value",
        "FAKEPRIVATEKEYMATERIAL",
    ];
    let path = write_input(
        "nosecrets",
        "mail leak-me@example.com\nkey AKIAIOSFODNN7EXAMPLE\npassword=sup3r-s3cret-value\n-----BEGIN PRIVATE KEY-----\nFAKEPRIVATEKEYMATERIAL\n-----END PRIVATE KEY-----\n",
    );
    let out = run_check(&path, &[]);
    let err = stderr_of(&out);
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout.is_empty(), "check mode must write no stdout output");
    for secret in secrets {
        assert!(
            !err.contains(secret),
            "secret {secret:?} leaked into the report:\n{err}"
        );
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn check_quiet_suppresses_per_finding_lines_but_keeps_the_summary() {
    let path = write_input("quiet", "contact a@b.com\n");
    let out = run_check(&path, &["--quiet"]);
    let err = stderr_of(&out);
    let p = path.display();
    assert_eq!(out.status.code(), Some(1));
    assert!(!err.contains(&format!("{p}:")), "stderr was:\n{err}");
    assert!(err.contains("email: 1"), "stderr was:\n{err}");
    assert!(err.contains("redact: found 1 potential secret(s)"));
    std::fs::remove_file(&path).ok();
}

#[test]
fn check_clean_input_exits_zero() {
    let path = write_input("clean", "the quick brown fox\n");
    let out = run_check(&path, &[]);
    let err = stderr_of(&out);
    assert_eq!(out.status.code(), Some(0));
    assert!(err.contains("redact: no secrets found"));
    std::fs::remove_file(&path).ok();
}
