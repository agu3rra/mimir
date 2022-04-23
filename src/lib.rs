use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, AddrParseError};
use clap::{ self, Command, Arg, lazy_static::lazy_static };

const MIMIR_AUTHOR: &str = "Andre Guerra";
const MIMIR_ABOUT: &str = "Mimir - TLS Security testing CLI";

#[derive(Debug)]
pub struct Config {
    pub show_ciphers: bool,
    pub test: bool,
    pub host: Option<String>,
    pub port: Option<String>,
}

pub fn get_args() -> Config {
    let matches = Command::new("mimir")
        .version(clap::crate_version!())
        .author(MIMIR_AUTHOR)
        .about(MIMIR_ABOUT)
        .arg(
            Arg::new("show_ciphers")
                .short('s')
                .long("show-ciphers")
                .help("displays supported protocols and cipher suites.")
                .takes_value(false)
                .required(false)
        )
        .arg(
            Arg::new("test")
                .short('t')
                .long("test")
                .help("test supported cipher suites.")
                .takes_value(false)
                .required_unless_present("show_ciphers")
        )
        .arg(
            Arg::new("host")
                .short('h')
                .long("host")
                .help("hostname or IP address to test against. E.g.: example.com, 10.18.23.11")
                .required_unless_present("show_ciphers")
                .value_name("HOST")
                .allow_invalid_utf8(false)
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .help("port number in which the service is served. E.g.: 443, 8443.")
                .required_unless_present("show_ciphers")
                .value_name("PORT")
                .allow_invalid_utf8(false)
        )
        .get_matches();

    Config {
        show_ciphers: matches.is_present("show_ciphers"),
        test: matches.is_present("test"),
        host: matches.value_of("host").map(|n| n.to_owned()),
        port: matches.value_of("port").map(|n| n.to_owned()),
    }
}

/// Determines if provided `target` string is in IP address V4/V6
/// 
pub fn is_host_ip(target: &str) -> bool {
    let ip_result: Result<IpAddr, AddrParseError> = target.parse();
    let ip = match ip_result {
        Ok(ip) => return true,
        Err(ip) => return false,
    };
}

#[test]
fn test_is_host_ip() {
    let test_cases = vec![
        // input, expected_response
        ("192.6.30.1", true),
        ("1.1.1.1", true),
        ("256.1.1.1", false),
        ("localhost", false),
        ("192.6.3", false),
        ("1234", false),
        ("2000:1284:f019:6884:65d5:11d9:535d:5967", true),
        ("20:184:f019:6884:65d5:11d9:53d:5967", true),
        ("2g00:1284:f019:6884:65d5:11d9:535d:5967", false),
        ("foobar", false),
        ("example.com", false),
    ];
    for case in test_cases {
        let (input, expected_output) = case;
        assert!(is_host_ip(input)==expected_output, "Test case failed: input={}; expected_output={}", input, expected_output);
    }
}

// #[tokio::main]
// pub async fn dns_lookup(target: &str) -> Vec<SocketAddr> {
//     let mut addresses = Vec::new();
//     for addr in net::lookup_host(target).await? {
//         addresses.push(addr);
//     }
//     addresses
// }
