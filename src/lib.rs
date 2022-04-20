use std::io;
use clap::{ Command, Arg };
use tokio::net;

const MIMIR_VERSION: &str = "0.1.0";
const MIMIR_AUTHOR: &str = "Andre Guerra";
const MIMIR_ABOUT: &str = "Mimir - Security testing CLI";

#[derive(Debug)]
pub struct Config {
    pub show_ciphers: bool,
    pub test: bool,
    pub host: Option<String>,
    pub port: Option<String>,
}

pub fn get_args() -> Config {
    let matches = Command::new("mimir")
        .version(MIMIR_VERSION)
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

#[tokio::main]
pub async fn dns_lookup(target: &str) -> io::Result<()> {
    for addr in net::lookup_host(target).await? {
        println!("address is {}", addr);
        println!("Debugging");
    }
    Ok(())
}
