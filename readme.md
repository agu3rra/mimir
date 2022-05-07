# Mimir: TLS Cipher Suite CLI Tester (work in-progress...)
Mimir is a figure in Norse mythology, renowned for his knowledge and wisdom, who is beheaded during the Æsir-Vanir War. Afterward, the god Odin carries around Mímir's head and it recites secret knowledge and counsel to him.

The objective of this CLI application is to tell you supported cipher-suites of any given HTTPS connection. It shall aid you in determining deprecated and unwanted ones that are know to be insecure.

![mimir](img/mimir.jpeg)

# Installation
`mimir` is a self contained binary written in Rust. Head to the [releases]() section of this repo and grab the one that matches your operating system. On Unix-based systems, make sure it has permission to execute (`chmod +x mimir`).

# Usage
```bash
$ mimir --version
$ mimir --test --host=example.com --port=8443
$ mimir --show-ciphers
```

# Program flow
1. Iterate thru all TLS protocols from SSLv2 to TLSv1.2;
1. Find the IP addresses of the target host;
1. Establish TCP socket connection;
1. Build a Client Hello message containing only the cipher suite to test. Message is in hex format;
1. Validate response to determine if cipher suite is supported;
1. Do this simultaneously for about X connections to make it faster. Create a default and let the user specifcy a custom value.

# References
* https://ssl-config.mozilla.org/
* https://github.com/nabla-c0d3/sslyze
