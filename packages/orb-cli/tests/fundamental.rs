mod testutils;

use assert_cmd::cargo::*;
use assert_cmd::prelude::*;
use insta::assert_snapshot;
use orb_mockhttp::TestServerBuilder;
use std::process::Command;
use testutils::sanitize_output;

#[test]
fn test_can_send_request() {
    let server = TestServerBuilder::new().build();
    server.on_request("/").respond_with(200, "Hello, World");

    // Run the orb CLI against our test server
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/"));
    cmd.assert().success();

    server.assert_requests(1);
}

#[test]
fn test_default_headers() {
    let server = TestServerBuilder::new().build();
    server.on_request("/").respond_with(200, "Hello, World");

    // Run the orb CLI against our test server
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/"));
    cmd.assert().success();

    assert_snapshot!(sanitize_output(&server.get_raw_request().unwrap()), @r"
    GET / HTTP/1.1
    accept: */*
    user-agent: orb/0.1.0
    host: 127.0.0.1:<PORT>
    ");

    server.assert_requests(1);
}

#[test]
fn test_form_raw() {
    let server = TestServerBuilder::new().build();
    server.on_request("/").respond_with(200, "Hello, World");

    // Run the orb CLI against our test server
    let mut cmd = Command::new(cargo_bin!("orb"));
    cmd.arg(server.url("/"))
        .arg("-X")
        .arg("POST")
        .arg("-F")
        .arg("field1=value1");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    assert_snapshot!(sanitize_output(&server.get_raw_request().unwrap()), @r#"
    POST / HTTP/1.1
    accept: */*
    user-agent: orb/0.1.0
    host: 127.0.0.1:<PORT>
    content-type: multipart/form-data; boundary=<BOUNDARY>
    content-length: 131

    --<BOUNDARY>
    Content-Disposition: form-data; name="field1"

    value1
    --<BOUNDARY>--
    "#);

    server.assert_requests(1);
}
