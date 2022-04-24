use assert_cmd::Command;
use predicates::prelude::predicate;
use clap;

#[test]
fn dies_no_args() {
    let mut cmd = Command::cargo_bin(clap::crate_name!()).unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("USAGE"));
}

#[test]
fn runs_list_ciphers() {
    let input_arguments = vec![
        "-s",
        "--show-ciphers",
    ];
    for argument in input_arguments {
        let mut cmd = Command::cargo_bin(clap::crate_name!()).unwrap();
        cmd.arg(argument).assert()
            .success()
            .stdout(predicate::str::contains("TLS protocol versions implemented for testing"));
    }
}

#[test]
fn test_insufficient_args() {
    let input_arguments = vec![
        "-t",    
        "--test",
    ];
    for argument in input_arguments {
        let mut cmd = Command::cargo_bin(clap::crate_name!()).unwrap();
        cmd.arg(argument);
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("requires a value but none was supplied"));
    }
}

#[test]
fn test_invalid_target() {
    let test_cases = vec![
        "--test 192.6.30.1",
        "--test localhost",
        "--test 1234",
        "--test 2000:1284:f019:6884:65d5:11d9:535d:5967",
        "--test 20:184:f019:6884:65d5:11d9:53d:5967",
        "--test 2g00:1284:f019:6884:65d5:11d9:535d:5967:443",
        "--test foobar",
        "--test example.com",
    ];
    for case in test_cases {
        let mut cmd = Command::cargo_bin(clap::crate_name!()).unwrap();
        let args: Vec<&str> = case.split(" ").collect();
        for argument in args { cmd.arg(argument); }
        cmd.assert()
            .failure()
            .stderr(predicates::str::contains("Error on address resolution"));
    }
}

#[test]
fn runs_tls_check() {
    let mut cmd = Command::cargo_bin(clap::crate_name!()).unwrap();
    // Testing against a server that has TLS1.1 enabled.
    let tests = vec![
        ("--test uol.com:443", "RESULT: Not compliant"),
        ("--test uol.com:443", "RESULT: Not compliant"), // more test cases to follow
    ];
    for test in tests {
        let (input, expected_output) = test;
        let args: Vec<&str> = input.split(" ").collect();
        let mut cmd = Command::cargo_bin(clap::crate_name!()).unwrap();
        for arg in args { cmd.arg(arg); }
        cmd.assert()
            .success()
            .stdout(predicates::str::contains(expected_output));
    }
}