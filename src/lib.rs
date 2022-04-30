use std::net::{SocketAddr};
use clap::{ self, Command, Arg };
use tokio::{self, net};
use std::io::{self, ErrorKind};

mod protocol;

#[derive(Debug)]
pub struct Config {
    pub show_ciphers: bool,
    pub test: Option<String>,
}

pub fn get_args() -> Config {
    let matches = Command::new("mimir")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about(clap::crate_description!())
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
                .help("tests supported cipher suites in target. e.g.: -t foo.com:443")
                .takes_value(true)
                .value_name("TARGET") 
                .allow_invalid_utf8(false)
                .required_unless_present("show_ciphers")
        )
        .get_matches();

    Config {
        show_ciphers: matches.is_present("show_ciphers"),
        test: matches.value_of("test").map(|n| n.to_owned()),
    }
}

pub fn show_ciphers() {
    let test_suite = protocol::TestSuite::new();
    println!("Summary:");
    let versions = test_suite.versions;
    println!("TLS protocol versions implemented for testing: {}\n--",versions.len());
    for version in versions {
        println!("Protocol: {:?}", version.protocol);
        println!("Ciphers count: {}\n-", version.ciphers.len());
        for cipher in version.ciphers {
            println!("{:?}", cipher)
        }
        println!("---");
    }
}

#[tokio::main]
pub async fn dns_lookup(target: &str) -> io::Result<Vec<SocketAddr>>{
    let mut addresses:Vec<SocketAddr> = Vec::new();
    for addr in net::lookup_host(target).await? {
        addresses.push(addr);
    }
    let amount_addresses = addresses.len();
    println!("{:?} IP addresses identified for provided input.", amount_addresses);
    if amount_addresses > 0 {
        return Ok(addresses)
    }
    return Err(io::Error::new(
        ErrorKind::AddrNotAvailable, 
        "Target provided cannot be reached")
    )
}

pub fn check_supported_ciphers(socket: SocketAddr) -> bool {
    println!("Attempting tests on: {:?}", socket);

    true
}
