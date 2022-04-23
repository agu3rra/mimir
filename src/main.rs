mod protocol;

fn main() {
    let args = mimir::get_args();
    if args.show_ciphers {
        println!("Summary:");
        let versions = protocol::tls_versions();
        println!("TLS protocol versions implemented for testing: {}\n--", versions.len());
        for version in versions {
            println!("Protocol: {:?}", version.protocol);
            println!("Ciphers count: {}\n-", version.ciphers.len());
            for cipher in version.ciphers {
                println!("{:?}", cipher)
            }
            println!("---");
        }
        std::process::exit(0)
    }
    if args.test {
        println!("### Welcome to Mimir ###");
        let host = args.host.unwrap();
        if mimir::is_host_ip(&host) {
            println!("You provided an IP address in the host field.");
        } else {
            println!("You provided a DNS record. We'll try to determine its IP address in the next step.");
        }
    }
}