mod testutils;

use assert_cmd::cargo::*;
use std::process::Command;
use test_case::test_case;
// Test that valid IPv6 connect-to rules pass validation
// Note: These tests only verify the validation passes, not the actual connection
// since that would require an IPv6-capable mock server
#[test_case(
    "example.com:80:[::1]:8080";
    "ipv6 target"
)]
#[test_case(
    "[::1]:80:127.0.0.1:8080";
    "ipv6 source"
)]
#[test_case(
    "[2001:db8::1]:80:[::1]:8080";
    "ipv6 both"
)]
#[test_case(
    "[::1]::[::1]:8080";
    "ipv6 wildcard port"
)]
fn test_connect_to_ipv6_validation_passes(connect_to: &str) {
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg("http://127.0.0.1:0/test") // Non-existent server
        .arg("--connect-to")
        .arg(connect_to)
        .arg("--connect-timeout")
        .arg("1"); // Quick timeout

    let output = cmd.output().unwrap();
    // The command will fail due to connection timeout/refused, but NOT due to validation
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Ensure it's not a validation error
    assert!(
        !stderr.contains("Invalid --connect-to format"),
        "IPv6 rule '{}' should be valid but got: {}",
        connect_to,
        stderr
    );
}

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
