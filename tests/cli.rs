use assert_cmd::Command;
use predicates::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn dies_no_args() -> TestResult {
    let mut cmd = Command::cargo_bin("mimir")?;
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("USAGE"));
    Ok(())
}

#[test]
fn runs_list_ciphers() {
    let input_arguments = vec![
        "-s",
        "--show-ciphers",
    ];
    for argument in input_arguments {
        let mut cmd = Command::cargo_bin("mimir").unwrap();
        cmd.arg(argument).assert()
            .success()
            .stdout(predicate::str::contains("TLS protocol versions implemented for testing"));
    }
}

#[test]
fn test_insufficient_args() {
    let input_arguments = vec![
        "--test",
        "--test --host=foo.com",
        "--test --port=1234",
    ];
    for argument in input_arguments {
        let mut cmd = Command::cargo_bin("mimir").unwrap();
        let args: Vec<&str> = argument.split(" ").collect();
        for arg in args { cmd.arg(arg); }
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("The following required arguments were not provided:"));
    }
}

#[test]
fn runs_tls_check() {
    let mut cmd = Command::cargo_bin("mimir").unwrap();
    // Testing against a server that has TLS1.1 enabled.
    let tests = vec![
        ("--test --host=uol.com --port=443", "RESULT: Not compliant"),
        ("--test --host=uol.com --port=443", "RESULT: Not compliant"), // more test cases to follow
    ];
    for test in tests {
        let (input, expected_output) = test;
        let args: Vec<&str> = input.split(" ").collect();
        let mut cmd = Command::cargo_bin("mimir").unwrap();
        for arg in args { cmd.arg(arg); }
        cmd.assert()
            .success()
            .stdout(predicates::str::contains(expected_output));
    }

    cmd.arg("--test --host=uol.com --port=443").assert()
        .success()
        .stdout(predicates::str::contains("RESULT: Not compliant"));
}