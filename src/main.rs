mod protocol;
use clap;

fn main() {
    println!("### Welcome to {} ###", clap::crate_name!());
    let test_suite = protocol::TestSuite::new();
    let args = mimir::get_args();
    if args.show_ciphers {
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
        std::process::exit(0)
    }
    let target = args.test.unwrap();
    let _ = match mimir::dns_lookup(&target){
        Ok(addresses) => {
            for address in addresses {
                println!("Attempting tests on: {:?}", address);
                // synchronous first then queue a bunch and send them simultaneously
                
                // establish connection to socket
                // build byte sequence for client hello
                // std::process::exit(0)
            }
        }
        Err(error) => { 
            eprintln!("Error on address resolution: {}", error);
            std::process::exit(1)
        }
    };
}