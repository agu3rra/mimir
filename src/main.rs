mod protocol;
use clap;

fn main() {
    println!("### Welcome to {} ###", clap::crate_name!());
    let args = mimir::get_args();
    if args.show_ciphers {
        mimir::show_ciphers();
        std::process::exit(0)
    }
    let target = args.test.unwrap();
    let _ = match mimir::dns_lookup(&target){
        Ok(addresses) => {
            for address in addresses {
                println!("foo");
                // match mimir::check_supported_ciphers(address) {
                //    std::process::exit(0)
                // }
            }
        }
        Err(error) => { 
            eprintln!("Error on address resolution: {}", error);
            std::process::exit(1)
        }
    };
}