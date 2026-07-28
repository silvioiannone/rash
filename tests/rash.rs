use std::io::Write;
use std::process::{Command, Stdio};

/// Execute the a `rash` command and returns the output.
///
/// Returns a tuple containing the following:
/// 1. Standard output
/// 2. Standard error
/// 3. Exit code
fn run(args: &[&str], stdin: &[u8]) -> (String, String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rash"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin)
        .expect("failed to write stdin");

    let output = child.wait_with_output().expect("failed to wait on child");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

#[test]
fn hashes_stdin_with_md5() {
    let (stdout, _, code) = run(&["md5"], b"abc");
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "900150983cd24fb0d6963f7d28e17f72");
}

#[test]
fn hashes_empty_stdin() {
    let (stdout, _, code) = run(&["md5"], b"");
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn rejects_unknown_algorithm() {
    let (_, stderr, code) = run(&["non_existing_algo"], b"abc");
    assert_ne!(code, 0);
    assert!(stderr.contains("invalid value") || stderr.contains("possible values"));
}

#[test]
fn requires_algo_argument() {
    let (_, stderr, code) = run(&[], b"abc");
    assert_ne!(code, 0);
    assert!(stderr.contains("ALGO") || stderr.contains("required"));
}

#[test]
fn hashes_a_file() {
    let mut path = std::env::temp_dir();
    path.push(format!("rash-test-{}.txt", std::process::id()));
    std::fs::write(&path, b"abc").unwrap();

    let (stdout, _, code) = run(&["md5", "-f", path.to_str().unwrap()], b"");

    std::fs::remove_file(&path).unwrap();

    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "900150983cd24fb0d6963f7d28e17f72");
}

#[test]
fn verifies_a_valid_hash() {
    let (_, _, code) = run(&["md5", "-v", "900150983cd24fb0d6963f7d28e17f72"], b"");
    assert_eq!(code, 0);
}

#[test]
fn verifies_an_invalid_hash() {
    let (_, stderr, code) = run(&["md5", "-v", "abc"], b"");
    assert_eq!(code, 1);
    assert!(stderr.contains("Validation error: Invalid hash length."));
}

#[test]
fn compares_a_matching_hash() {
    let (_, _, code) = run(&["md5", "-c", "900150983cd24fb0d6963f7d28e17f72"], b"abc");
    assert_eq!(code, 0);
}

#[test]
fn compares_a_non_matching_hash() {
    let (_, _, code) = run(&["md5", "-c", "900150983cd24fb0d6963f7d28e17f72"], b"cba");
    assert_eq!(code, 1);
}
