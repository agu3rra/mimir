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
fn runs_tls_check() {
    let mut cmd = Command::cargo_bin("mimir").unwrap();
    // Testing against a server that has TLS1.1 enabled.
    cmd.arg("--test --host=uol.com --port=443").assert()
        .success()
        .stdout(predicates::str::contains("RESULT: Not compliant"));
}