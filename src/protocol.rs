use rand::{Rng, RngCore};

#[derive(Debug, Clone)]
pub struct Protocol {
    pub name: &'static str,
    hex_value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Cipher {
    pub name: &'static str,
    hex_value: Vec<u8>,
    relevant_bytes: u8,  // because SSLv2.0 uses 3 byte representations we will need to fit into an u16
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub name: &'static str,
    hex_value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Version {
    pub protocol: Protocol,
    pub ciphers: Vec<Cipher>,
    pub ext_support_groups: Option<Vec<Extension>>,
    pub ext_ec_point_formats: Option<Vec<Extension>>,
}

impl Version {
    fn new(
        protocol: Protocol,
        ciphers: Vec<Cipher>,
        ext_support_groups: Option<Vec<Extension>>,
        ext_ec_point_formats: Option<Vec<Extension>>,
    ) -> Version {
        Version { 
            protocol: protocol,
            ciphers: ciphers,  
            ext_support_groups: ext_support_groups,
            ext_ec_point_formats: ext_ec_point_formats,
        }
    }

    // generates client hello byte stream for the given input
    fn client_hello(&self, cipher: Cipher) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut challenge = [0u8; 16];
        rng.fill(&mut challenge[..]);  // random 16 bytes - no need for truly random as this is for checking cipher support
        println!("Challenge: {:?}", challenge);
        let session_length: Vec<u8> = (0x0000 as u16).to_be_bytes().to_vec();
        let relevant_cipher_index_start: usize = cipher.hex_value.len() - cipher.relevant_bytes as usize;
        let cipher_hex: Vec<u8> = cipher.hex_value[relevant_cipher_index_start..].to_vec();
        [
            HANDSHAKE_CLIENT_HELLO.to_be_bytes().to_vec(),
            self.protocol.hex_value.clone(),
            (cipher.relevant_bytes as u16).to_be_bytes().to_vec(),
            session_length,
            cipher_hex,
            challenge.to_vec(),
        ].concat()
    }
}

#[test]
fn test_client_hello() {
    let test_version = Version::new(
        Protocol { name: "FooBar", hex_value: (0x0102 as u16).to_be_bytes().to_vec() },
        vec![Cipher { name: "dummy", hex_value: (0x14e2f0 as u32).to_be_bytes().to_vec(), relevant_bytes: 3 }],
        None,
        None,
    );
    let hello = test_version.client_hello(Cipher { name: "dummy", hex_value: (0x14e2f0 as u32).to_be_bytes().to_vec(), relevant_bytes: 3 });
    println!("{:?}", hello);
    assert!(true)
}

pub struct TestSuite {
    pub versions: Vec<Version>
}
impl TestSuite {
    pub fn new() -> TestSuite {
        let ssl20 = Version::new(
            Protocol { name: "SSLv2.0", hex_value: SSLV20.to_be_bytes().to_vec() }, 
            vec![
                Cipher { name: "SSL2_RC4_128_WITH_MD5", hex_value: SSL2_RC4_128_WITH_MD5.to_be_bytes().to_vec(), relevant_bytes: 3 },
                Cipher { name: "SSL2_RC4_128_EXPORT40_WITH_MD5", hex_value: SSL2_RC4_128_EXPORT40_WITH_MD5.to_be_bytes().to_vec(), relevant_bytes: 3 },
                Cipher { name: "SSL2_RC2_128_CBC_WITH_MD5", hex_value: SSL2_RC2_128_CBC_WITH_MD5.to_be_bytes().to_vec(), relevant_bytes: 3 },
                Cipher { name: "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5", hex_value: SSL2_RC2_128_CBC_EXPORT40_WITH_MD5.to_be_bytes().to_vec(), relevant_bytes: 3 },
                Cipher { name: "SSL2_IDEA_128_CBC_WITH_MD5", hex_value: SSL2_IDEA_128_CBC_WITH_MD5.to_be_bytes().to_vec(), relevant_bytes: 3 },
                Cipher { name: "SSL2_DES_64_CBC_WITH_MD5", hex_value: SSL2_DES_64_CBC_WITH_MD5.to_be_bytes().to_vec(), relevant_bytes: 3 },
                Cipher { name: "SSL2_DES_192_EDE3_CBC_WITH_MD5", hex_value: SSL2_DES_192_EDE3_CBC_WITH_MD5.to_be_bytes().to_vec(), relevant_bytes: 3 },
            ],
            None,
            None
        );
        let ciphers_ssl30_tls10_tls11 = vec![
            Cipher { name: "TLS_RSA_WITH_NULL_MD5", hex_value: TLS_RSA_WITH_NULL_MD5.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_NULL_SHA", hex_value: TLS_RSA_WITH_NULL_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", hex_value: TLS_RSA_EXPORT_WITH_RC4_40_MD5.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_RC4_128_MD5", hex_value: TLS_RSA_WITH_RC4_128_MD5.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_RC4_128_SHA", hex_value: TLS_RSA_WITH_RC4_128_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", hex_value: TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_IDEA_CBC_SHA", hex_value: TLS_RSA_WITH_IDEA_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", hex_value: TLS_RSA_EXPORT_WITH_DES40_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_DES_CBC_SHA", hex_value: TLS_RSA_WITH_DES_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_RSA_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_DSS_WITH_DES_CBC_SHA", hex_value: TLS_DH_DSS_WITH_DES_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_RSA_WITH_DES_CBC_SHA", hex_value: TLS_DH_RSA_WITH_DES_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", hex_value: TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_DSS_WITH_DES_CBC_SHA", hex_value: TLS_DHE_DSS_WITH_DES_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", hex_value: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_DES_CBC_SHA", hex_value: TLS_DHE_RSA_WITH_DES_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5", hex_value: TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_ANON_WITH_RC4_128_MD5", hex_value: TLS_DH_ANON_WITH_RC4_128_MD5.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA", hex_value: TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_ANON_WITH_DES_CBC_SHA", hex_value: TLS_DH_ANON_WITH_DES_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_AES_128_CBC_SHA", hex_value: TLS_RSA_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_DSS_WITH_AES_128_CBC_SHA", hex_value: TLS_DH_DSS_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_RSA_WITH_AES_128_CBC_SHA", hex_value: TLS_DH_RSA_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", hex_value: TLS_DHE_DSS_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", hex_value: TLS_DHE_RSA_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_ANON_WITH_AES_128_CBC_SHA", hex_value: TLS_DH_ANON_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_AES_256_CBC_SHA", hex_value: TLS_RSA_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_DSS_WITH_AES_256_CBC_SHA", hex_value: TLS_DH_DSS_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_RSA_WITH_AES_256_CBC_SHA", hex_value: TLS_DH_RSA_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", hex_value: TLS_DHE_DSS_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", hex_value: TLS_DHE_RSA_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_ANON_WITH_AES_256_CBC_SHA", hex_value: TLS_DH_ANON_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", hex_value: TLS_RSA_WITH_CAMELLIA_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", hex_value: TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", hex_value: TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", hex_value: TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", hex_value: TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA", hex_value: TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", hex_value: TLS_RSA_WITH_CAMELLIA_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", hex_value: TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", hex_value: TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", hex_value: TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", hex_value: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA", hex_value: TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_SEED_CBC_SHA", hex_value: TLS_RSA_WITH_SEED_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_DSS_WITH_SEED_CBC_SHA", hex_value: TLS_DH_DSS_WITH_SEED_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_RSA_WITH_SEED_CBC_SHA", hex_value: TLS_DH_RSA_WITH_SEED_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_DSS_WITH_SEED_CBC_SHA", hex_value: TLS_DHE_DSS_WITH_SEED_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_SEED_CBC_SHA", hex_value: TLS_DHE_RSA_WITH_SEED_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DH_ANON_WITH_SEED_CBC_SHA", hex_value: TLS_DH_ANON_WITH_SEED_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ECDSA_WITH_NULL_SHA", hex_value: TLS_ECDH_ECDSA_WITH_NULL_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", hex_value: TLS_ECDH_ECDSA_WITH_RC4_128_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", hex_value: TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", hex_value: TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_NULL_SHA", hex_value: TLS_ECDHE_ECDSA_WITH_NULL_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", hex_value: TLS_ECDHE_ECDSA_WITH_RC4_128_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", hex_value: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", hex_value: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_RSA_WITH_NULL_SHA", hex_value: TLS_ECDH_RSA_WITH_NULL_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_RSA_WITH_RC4_128_SHA", hex_value: TLS_ECDH_RSA_WITH_RC4_128_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", hex_value: TLS_ECDH_RSA_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", hex_value: TLS_ECDH_RSA_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_NULL_SHA", hex_value: TLS_ECDHE_RSA_WITH_NULL_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", hex_value: TLS_ECDHE_RSA_WITH_RC4_128_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", hex_value: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", hex_value: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ANON_WITH_NULL_SHA", hex_value: TLS_ECDH_ANON_WITH_NULL_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ANON_WITH_RC4_128_SHA", hex_value: TLS_ECDH_ANON_WITH_RC4_128_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA", hex_value: TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA", hex_value: TLS_ECDH_ANON_WITH_AES_128_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA", hex_value: TLS_ECDH_ANON_WITH_AES_256_CBC_SHA.to_be_bytes().to_vec(), relevant_bytes: 2 },
        ];
        let ssl30 = Version::new(
            Protocol { name: "SSLv3.0", hex_value: SSLV30.to_be_bytes().to_vec() },
            ciphers_ssl30_tls10_tls11.clone(),
            None,
            None
        );
        let ext_support_groups = vec![
            Extension { name: "GROUP_SECP256R1", hex_value: GROUP_SECP256R1.to_be_bytes().to_vec() },
            Extension { name: "GROUP_SECP384R1", hex_value: GROUP_SECP384R1.to_be_bytes().to_vec() },
            Extension { name: "GROUP_SECP521R1", hex_value: GROUP_SECP521R1.to_be_bytes().to_vec() },
            Extension { name: "GROUP_X25519", hex_value: GROUP_X25519.to_be_bytes().to_vec() },
            Extension { name: "GROUP_X448", hex_value: GROUP_X448.to_be_bytes().to_vec() },
        ];
        let ext_ec_point_formats = vec![
            Extension { name: "EC_POINT_FORMAT_UNCOMPRESSED", hex_value: EC_POINT_FORMAT_UNCOMPRESSED.to_be_bytes().to_vec() },
            Extension { name: "EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME", hex_value: EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME.to_be_bytes().to_vec() },
            Extension { name: "EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2", hex_value: EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2.to_be_bytes().to_vec() },
        ];

        let tls10 = Version::new(
            Protocol { name: "TLSv1.0", hex_value: TLSV10.to_be_bytes().to_vec() },
            ciphers_ssl30_tls10_tls11.clone(),
            Some(ext_support_groups.clone()),
            Some(ext_ec_point_formats.clone()),
        );
    
        let tls11 = Version::new(
            Protocol { name: "TLSv1.1", hex_value: TLSV11.to_be_bytes().to_vec() },
            ciphers_ssl30_tls10_tls11.clone(),
            Some(ext_support_groups.clone()),
            Some(ext_ec_point_formats.clone()),
        );
    
        let mut ciphers_tls12 = vec![
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", hex_value: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", hex_value: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", hex_value: TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", hex_value: TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", hex_value: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", hex_value: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", hex_value: TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", hex_value: TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", hex_value: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", hex_value: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", hex_value: TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", hex_value: TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", hex_value: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", hex_value: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", hex_value: TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", hex_value: TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_ARIA_128_GCM_SHA256", hex_value: TLS_RSA_WITH_ARIA_128_GCM_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_ARIA_256_GCM_SHA384", hex_value: TLS_RSA_WITH_ARIA_256_GCM_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", hex_value: TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", hex_value: TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", hex_value: TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", hex_value: TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", hex_value: TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", hex_value: TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", hex_value: TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", hex_value: TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", hex_value: TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", hex_value: TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", hex_value: TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", hex_value: TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_AES_128_CCM", hex_value: TLS_RSA_WITH_AES_128_CCM.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_AES_256_CCM", hex_value: TLS_RSA_WITH_AES_256_CCM.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_AES_128_CCM", hex_value: TLS_DHE_RSA_WITH_AES_128_CCM.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_AES_256_CCM", hex_value: TLS_DHE_RSA_WITH_AES_256_CCM.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_AES_128_CCM_8", hex_value: TLS_RSA_WITH_AES_128_CCM_8.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_RSA_WITH_AES_256_CCM_8", hex_value: TLS_RSA_WITH_AES_256_CCM_8.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_AES_128_CCM_8", hex_value: TLS_DHE_RSA_WITH_AES_128_CCM_8.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_AES_256_CCM_8", hex_value: TLS_DHE_RSA_WITH_AES_256_CCM_8.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", hex_value: TLS_ECDHE_ECDSA_WITH_AES_128_CCM.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", hex_value: TLS_ECDHE_ECDSA_WITH_AES_256_CCM.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", hex_value: TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", hex_value: TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", hex_value: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", hex_value: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
            Cipher { name: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", hex_value: TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256.to_be_bytes().to_vec(), relevant_bytes: 2 },
        ];
        ciphers_tls12.extend(ciphers_ssl30_tls10_tls11);
        
        let tls12 = Version::new(
            Protocol { name: "TLSv1.2", hex_value: TLSV12.to_be_bytes().to_vec() },
            ciphers_tls12.clone(),
            Some(ext_support_groups.clone()),
            Some(ext_ec_point_formats.clone()),
        );
    
        TestSuite {
            versions: vec![ssl20, ssl30, tls10, tls11, tls12],
        }
    }
}


// TLS Protocol bytes as defined in RFC-8446
// https://datatracker.ietf.org/doc/html/rfc8446
const CONTENT_HANDSHAKE: u8 = 0x16;
const CONTENT_ALERT: u8 = 0x15;

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

// For increased compatibility, include this "cipher" on all requests from
// SSLv3.0 onwards. Details on RFC 5746 section 3.3.
const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;

// Commenting out as Muspell didn't have it. Perhaps TLS 1.3 requires these?
// SignatureAlgorithm 
//const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
//const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
//const ECDSA_SECP521R1_SHA512: u16 = 0x0603;
//const ED25519: u16 = 0x0807;
//const ED448: u16 = 0x0808;
//const RSA_PSS_PSS_SHA256: u16 = 0x0809;
//const RSA_PSS_PSS_SHA384: u16 = 0x080A;
//const RSA_PSS_PSS_SHA512: u16 = 0x080B;
//const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
//const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
//const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
//const RSA_PKCS1_SHA256: u16 = 0x0401;
//const RSA_PKCS1_SHA384: u16 = 0x0501;
//const RSA_PKCS1_SHA512: u16 = 0x0601;
//const SHA224_ECDSA: u16 = 0x0303;
//const SHA224_RSA: u16 = 0x0301;
//const SHA224_DSA: u16 = 0x0302;
//const SHA256_DSA: u16 = 0x0402;
//const SHA384_DSA: u16 = 0x0502;
//const SHA512_DSA: u16 = 0x0602;

// Protocols
const SSLV20: u16 = 0x0002;
const SSLV30: u16 = 0x0300;
const TLSV10: u16 = 0x0301;
const TLSV11: u16 = 0x0302;
const TLSV12: u16 = 0x0303;
//const TLSV13: u16 = 0x0304;

// Ciphers
// SSL2.0
const SSL2_RC4_128_WITH_MD5: u32 = 0x010080;
const SSL2_RC4_128_EXPORT40_WITH_MD5: u32 = 0x020080;
const SSL2_RC2_128_CBC_WITH_MD5: u32 = 0x030080;
const SSL2_RC2_128_CBC_EXPORT40_WITH_MD5: u32 = 0x040080;
const SSL2_IDEA_128_CBC_WITH_MD5: u32 = 0x050080;
const SSL2_DES_64_CBC_WITH_MD5: u32 = 0x060040;
const SSL2_DES_192_EDE3_CBC_WITH_MD5: u32 = 0x0700c0;
// SSL3.0and up
const TLS_RSA_WITH_NULL_MD5: u32 = 0x0001;
const TLS_RSA_WITH_NULL_SHA: u32 = 0x0002;
const TLS_RSA_EXPORT_WITH_RC4_40_MD5: u32 = 0x0003;
const TLS_RSA_WITH_RC4_128_MD5: u32 = 0x0004;
const TLS_RSA_WITH_RC4_128_SHA: u32 = 0x0005;
const TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5: u32 = 0x0006;
const TLS_RSA_WITH_IDEA_CBC_SHA: u32 = 0x0007;
const TLS_RSA_EXPORT_WITH_DES40_CBC_SHA: u32 = 0x0008;
const TLS_RSA_WITH_DES_CBC_SHA: u32 = 0x0009;
const TLS_RSA_WITH_3DES_EDE_CBC_SHA: u32 = 0x000a;
const TLS_DH_DSS_WITH_DES_CBC_SHA: u32 = 0x000c;
const TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA: u32 = 0x000d;
const TLS_DH_RSA_WITH_DES_CBC_SHA: u32 = 0x000f;
const TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA: u32 = 0x0010;
const TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA: u32 = 0x0011;
const TLS_DHE_DSS_WITH_DES_CBC_SHA: u32 = 0x0012;
const TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA: u32 = 0x0013;
const TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA: u32 = 0x0014;
const TLS_DHE_RSA_WITH_DES_CBC_SHA: u32 = 0x0015;
const TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: u32 = 0x0016;
const TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5: u32 = 0x0017;
const TLS_DH_ANON_WITH_RC4_128_MD5: u32 = 0x0018;
const TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA: u32 = 0x0019;
const TLS_DH_ANON_WITH_DES_CBC_SHA: u32 = 0x001a;
const TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA: u32 = 0x001b;
const TLS_RSA_WITH_AES_128_CBC_SHA: u32 = 0x002f;
const TLS_DH_DSS_WITH_AES_128_CBC_SHA: u32 = 0x0030;
const TLS_DH_RSA_WITH_AES_128_CBC_SHA: u32 = 0x0031;
const TLS_DHE_DSS_WITH_AES_128_CBC_SHA: u32 = 0x0032;
const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: u32 = 0x0033;
const TLS_DH_ANON_WITH_AES_128_CBC_SHA: u32 = 0x0034;
const TLS_RSA_WITH_AES_256_CBC_SHA: u32 = 0x0035;
const TLS_DH_DSS_WITH_AES_256_CBC_SHA: u32 = 0x0036;
const TLS_DH_RSA_WITH_AES_256_CBC_SHA: u32 = 0x0037;
const TLS_DHE_DSS_WITH_AES_256_CBC_SHA: u32 = 0x0038;
const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: u32 = 0x0039;
const TLS_DH_ANON_WITH_AES_256_CBC_SHA: u32 = 0x003a;
const TLS_RSA_WITH_CAMELLIA_128_CBC_SHA: u32 = 0x0041;
const TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA: u32 = 0x0042;
const TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA: u32 = 0x0043;
const TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA: u32 = 0x0044;
const TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA: u32 = 0x0045;
const TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA: u32 = 0x0046;
const TLS_RSA_WITH_CAMELLIA_256_CBC_SHA: u32 = 0x0084;
const TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA: u32 = 0x0085;
const TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA: u32 = 0x0086;
const TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA: u32 = 0x0087;
const TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA: u32 = 0x0088;
const TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA: u32 = 0x0089;
const TLS_RSA_WITH_SEED_CBC_SHA: u32 = 0x0096;
const TLS_DH_DSS_WITH_SEED_CBC_SHA: u32 = 0x0097;
const TLS_DH_RSA_WITH_SEED_CBC_SHA: u32 = 0x0098;
const TLS_DHE_DSS_WITH_SEED_CBC_SHA: u32 = 0x0099;
const TLS_DHE_RSA_WITH_SEED_CBC_SHA: u32 = 0x009a;
const TLS_DH_ANON_WITH_SEED_CBC_SHA: u32 = 0x009b;
const TLS_ECDH_ECDSA_WITH_NULL_SHA: u32 = 0xc001;
const TLS_ECDH_ECDSA_WITH_RC4_128_SHA: u32 = 0xc002;
const TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA: u32 = 0xc003;
const TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA: u32 = 0xc004;
const TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA: u32 = 0xc005;
const TLS_ECDHE_ECDSA_WITH_NULL_SHA: u32 = 0xc006;
const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: u32 = 0xc007;
const TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: u32 = 0xc008;
const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u32 = 0xc009;
const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u32 = 0xc00a;
const TLS_ECDH_RSA_WITH_NULL_SHA: u32 = 0xc00b;
const TLS_ECDH_RSA_WITH_RC4_128_SHA: u32 = 0xc00c;
const TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA: u32 = 0xc00d;
const TLS_ECDH_RSA_WITH_AES_128_CBC_SHA: u32 = 0xc00e;
const TLS_ECDH_RSA_WITH_AES_256_CBC_SHA: u32 = 0xc00f;
const TLS_ECDHE_RSA_WITH_NULL_SHA: u32 = 0xc010;
const TLS_ECDHE_RSA_WITH_RC4_128_SHA: u32 = 0xc011;
const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: u32 = 0xc012;
const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u32 = 0xc013;
const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u32 = 0xc014;
const TLS_ECDH_ANON_WITH_NULL_SHA: u32 = 0xc015;
const TLS_ECDH_ANON_WITH_RC4_128_SHA: u32 = 0xc016;
const TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA: u32 = 0xc017;
const TLS_ECDH_ANON_WITH_AES_128_CBC_SHA: u32 = 0xc018;
const TLS_ECDH_ANON_WITH_AES_256_CBC_SHA: u32 = 0xc019;
// TLS 1.2 and up
const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u32 = 0xc023;
const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: u32 = 0xc024;
const TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256: u32 = 0xc025;
const TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384: u32 = 0xc026;
const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u32 = 0xc027;
const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: u32 = 0xc028;
const TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256: u32 = 0xc029;
const TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384: u32 = 0xc02a;
const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u32 = 0xc02b;
const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u32 = 0xc02c;
const TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256: u32 = 0xc02d;
const TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384: u32 = 0xc02e;
const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u32 = 0xc02f;
const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u32 = 0xc030;
const TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256: u32 = 0xc031;
const TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384: u32 = 0xc032;
const TLS_RSA_WITH_ARIA_128_GCM_SHA256: u32 = 0xc050;
const TLS_RSA_WITH_ARIA_256_GCM_SHA384: u32 = 0xc051;
const TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256: u32 = 0xc052;
const TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384: u32 = 0xc053;
const TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256: u32 = 0xc056;
const TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384: u32 = 0xc057;
const TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256: u32 = 0xc05c;
const TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384: u32 = 0xc05d;
const TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256: u32 = 0xc060;
const TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384: u32 = 0xc061;
const TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: u32 = 0xc072;
const TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: u32 = 0xc073;
const TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: u32 = 0xc076;
const TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384: u32 = 0xc077;
const TLS_RSA_WITH_AES_128_CCM: u32 = 0xc09c;
const TLS_RSA_WITH_AES_256_CCM: u32 = 0xc09d;
const TLS_DHE_RSA_WITH_AES_128_CCM: u32 = 0xc09e;
const TLS_DHE_RSA_WITH_AES_256_CCM: u32 = 0xc09f;
const TLS_RSA_WITH_AES_128_CCM_8: u32 = 0xc0a0;
const TLS_RSA_WITH_AES_256_CCM_8: u32 = 0xc0a1;
const TLS_DHE_RSA_WITH_AES_128_CCM_8: u32 = 0xc0a2;
const TLS_DHE_RSA_WITH_AES_256_CCM_8: u32 = 0xc0a3;
const TLS_ECDHE_ECDSA_WITH_AES_128_CCM: u32 = 0xc0ac;
const TLS_ECDHE_ECDSA_WITH_AES_256_CCM: u32 = 0xc0ad;
const TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: u32 = 0xc0ae;
const TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: u32 = 0xc0af;
const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u32 = 0xcca8;
const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u32 = 0xcca9;
const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u32 = 0xccaa;
// TLS1.3 and up
// const TLS_CHACHA20_POLY1305_SHA256: u32 = 0x1303;
// const TLS_AES_256_GCM_SHA384: u32 = 0x1302;
// const TLS_AES_128_GCM_SHA256: u32 = 0x1301;

// Extensions supported from TLS 1.0 and up
// SupportGroup {
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;
const GROUP_SECP521R1: u16 = 0x0019;
const GROUP_X25519: u16 = 0x001d;
const GROUP_X448: u16 = 0x001e;
// EcPointFormats
const EC_POINT_FORMAT_UNCOMPRESSED: u8 = 0x00;
const EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME: u8 = 0x01;
const EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2: u8 = 0x02;