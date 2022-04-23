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
        // determine if host is a DNS entry or IP address (IPV4/6)
        println!("Resolving IP addresses for target: {}", args.host.unwrap());
        println!("Found the following valid IP's:");
    }
}