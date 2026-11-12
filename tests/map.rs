//! Integration tests for reversible masking (--map / --restore).

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&std::ffi::OsStr], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_redact"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn mask_then_restore_gives_the_input_back() {
    let dir = tempfile::tempdir().unwrap();
    let map = dir.path().join("map.json");
    let input = "From: taro@example.com\nTel: 090-1234-5678\nMy Number: 1234 5678 9018\n";
    let masked = run(&["--map".as_ref(), map.as_os_str()], input);
    assert!(
        masked.status.success(),
        "{}",
        String::from_utf8_lossy(&masked.stderr)
    );
    let text = String::from_utf8(masked.stdout).unwrap();
    assert_eq!(
        text,
        "From: [EMAIL_1]\nTel: [JP_PHONE_1]\nMy Number: [MY_NUMBER_1]\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&map).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // The answer that comes back may move tokens around.
    let reply = "Reply to [EMAIL_1] or call [JP_PHONE_1]. [UNKNOWN_1] stays.";
    let restored = run(
        &["--restore".as_ref(), "--map".as_ref(), map.as_os_str()],
        reply,
    );
    assert!(restored.status.success());
    assert_eq!(
        String::from_utf8(restored.stdout).unwrap(),
        "Reply to taro@example.com or call 090-1234-5678. [UNKNOWN_1] stays."
    );
    assert!(String::from_utf8_lossy(&restored.stderr).contains("restored 2 value(s)"));
}

#[test]
fn a_map_file_that_is_something_else_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let other = dir.path().join("notes.txt");
    std::fs::write(&other, "keep me").unwrap();
    let o = run(&["--map".as_ref(), other.as_os_str()], "a@example.com");
    assert!(!o.status.success());
    assert_eq!(std::fs::read_to_string(&other).unwrap(), "keep me");
    let o = run(&["--restore".as_ref(), "a".as_ref()], "x");
    assert!(!o.status.success(), "--restore needs --map");
    let o = run(
        &["--check".as_ref(), "--map".as_ref(), other.as_os_str()],
        "x",
    );
    assert!(!o.status.success());
}
