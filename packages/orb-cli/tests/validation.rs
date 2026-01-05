mod testutils;

use assert_cmd::cargo::*;
use std::process::Command;
use test_case::test_case;

// Test conflict validation
#[test_case(
    "-d 'data' --json '{}'",
    "error: the argument '--data <DATA>' cannot be used with '--json <JSON>'";
    "data and json"
)]
#[test_case(
    "-d 'data' -F 'field=value'",
    "error: the argument '--data <DATA>' cannot be used with '--form <FORM>'";
    "data and form"
)]
#[test_case(
    "--json '{}' -F 'field=value'",
    "error: the argument '--json <JSON>' cannot be used with '--form <FORM>'";
    "json and form"
)]
fn test_conflicts(options: &str, expected_error: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    let args: Vec<&str> = options.split_whitespace().collect();
    cmd.arg("http://127.0.0.1:0/test");
    for arg in args {
        cmd.arg(arg);
    }

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(expected_error));
}
