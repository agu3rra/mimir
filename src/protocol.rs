// TLS Protocol bytes as defined in RFC-8446
// https://datatracker.ietf.org/doc/html/rfc8446
const CONTENT_HANDSHAKE: i32 = 0x16;
const CONTENT_ALERT: i32 = 0x15;

const HANDSHAKE_CLIENT_HELLO: i32 = 0x01;
const HANDSHAKE_SERVER_HELLO: i32 = 0x02;

// For increased compatibility, include this "cipher" on all requests from
// SSLv3.0 onwards. Details on RFC 5746 section 3.3.
const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: i32 = 0x00ff;


// Commenting out as Muspell didn't have it. Perhaps TLS 1.3 requires these?
// #[derive(Debug)]
// enum SignatureAlgorithm {
//     ECDSA_SECP256R1_SHA256 = 0x0403,
//     ECDSA_SECP384R1_SHA384 = 0x0503,
//     ECDSA_SECP521R1_SHA512 = 0x0603,
//     ED25519 = 0x0807,
//     ED448 = 0x0808,
//     RSA_PSS_PSS_SHA256 = 0x0809,
//     RSA_PSS_PSS_SHA384 = 0x080A,
//     RSA_PSS_PSS_SHA512 = 0x080B,
//     RSA_PSS_RSAE_SHA256 = 0x0804,
//     RSA_PSS_RSAE_SHA384 = 0x0805,
//     RSA_PSS_RSAE_SHA512 = 0x0806,
//     RSA_PKCS1_SHA256 = 0x0401,
//     RSA_PKCS1_SHA384 = 0x0501,
//     RSA_PKCS1_SHA512 = 0x0601,
//     SHA224_ECDSA = 0x0303,
//     SHA224_RSA = 0x0301,
//     SHA224_DSA = 0x0302,
//     SHA256_DSA = 0x0402,
//     SHA384_DSA = 0x0502,
//     SHA512_DSA = 0x0602,
// }

#[derive(Debug)]
pub enum Protocol {
    SSLV20 = 0x0002,
    SSLV30 = 0x0300,
    TLSV10 = 0x0301,
    TLSV11 = 0x0302,
    TLSV12 = 0x0303,
    // TLSV13 = 0x0304,
}

#[derive(Debug, Clone)]
pub enum Cipher {
    SSL2_RC4_128_WITH_MD5 = 0x010080,
    SSL2_RC4_128_EXPORT40_WITH_MD5 = 0x020080,
    SSL2_RC2_128_CBC_WITH_MD5 = 0x030080,
    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5 = 0x040080,
    SSL2_IDEA_128_CBC_WITH_MD5 = 0x050080,
    SSL2_DES_64_CBC_WITH_MD5 = 0x060040,
    SSL2_DES_192_EDE3_CBC_WITH_MD5 = 0x0700c0,

    // SSL3.0 and up
    TLS_RSA_WITH_NULL_MD5 = 0x0001,
    TLS_RSA_WITH_NULL_SHA = 0x0002,
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003,
    TLS_RSA_WITH_RC4_128_MD5 = 0x0004,
    TLS_RSA_WITH_RC4_128_SHA = 0x0005,
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006,
    TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007,
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008,
    TLS_RSA_WITH_DES_CBC_SHA = 0x0009,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a,
    TLS_DH_DSS_WITH_DES_CBC_SHA = 0x000c,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000d,
    TLS_DH_RSA_WITH_DES_CBC_SHA = 0x000f,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010,
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011,
    TLS_DHE_DSS_WITH_DES_CBC_SHA = 0x0012,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013,
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014,
    TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x0015,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016,
    TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5 = 0x0017,
    TLS_DH_ANON_WITH_RC4_128_MD5 = 0x0018,
    TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA = 0x0019,
    TLS_DH_ANON_WITH_DES_CBC_SHA = 0x001a,
    TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA = 0x001b,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
    TLS_DH_ANON_WITH_AES_128_CBC_SHA = 0x0034,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
    TLS_DH_ANON_WITH_AES_256_CBC_SHA = 0x003a,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041,
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0042,
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043,
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0044,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045,
    TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA = 0x0046,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084,
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0085,
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086,
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0087,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088,
    TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA = 0x0089,
    TLS_RSA_WITH_SEED_CBC_SHA = 0x0096,
    TLS_DH_DSS_WITH_SEED_CBC_SHA = 0x0097,
    TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098,
    TLS_DHE_DSS_WITH_SEED_CBC_SHA = 0x0099,
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009a,
    TLS_DH_ANON_WITH_SEED_CBC_SHA = 0x009b,
    TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xc001,
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xc002,
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc003,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xc004,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xc005,
    TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xc006,
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xc007,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc008,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a,
    TLS_ECDH_RSA_WITH_NULL_SHA = 0xc00b,
    TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xc00c,
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xc00d,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xc00e,
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xc00f,
    TLS_ECDHE_RSA_WITH_NULL_SHA = 0xc010,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xc011,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
    TLS_ECDH_ANON_WITH_NULL_SHA = 0xc015,
    TLS_ECDH_ANON_WITH_RC4_128_SHA = 0xc016,
    TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA = 0xc017,
    TLS_ECDH_ANON_WITH_AES_128_CBC_SHA = 0xc018,
    TLS_ECDH_ANON_WITH_AES_256_CBC_SHA = 0xc019,

    // TLS 1.2 and up
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc025,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc026,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xc029,
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xc02a,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02d,
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02e,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xc031,
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xc032,
    TLS_RSA_WITH_ARIA_128_GCM_SHA256 = 0xc050,
    TLS_RSA_WITH_ARIA_256_GCM_SHA384 = 0xc051,
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xc052,
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xc053,
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = 0xc056,
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = 0xc057,
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xc05c,
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xc05d,
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xc060,
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xc061,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc072,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc073,
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc076,
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc077,
    TLS_RSA_WITH_AES_128_CCM = 0xc09c,
    TLS_RSA_WITH_AES_256_CCM = 0xc09d,
    TLS_DHE_RSA_WITH_AES_128_CCM = 0xc09e,
    TLS_DHE_RSA_WITH_AES_256_CCM = 0xc09f,
    TLS_RSA_WITH_AES_128_CCM_8 = 0xc0a0,
    TLS_RSA_WITH_AES_256_CCM_8 = 0xc0a1,
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xc0a2,
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xc0a3,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xc0ac,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xc0ad,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xc0ae,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xc0af,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa,

    // TLS1.3 and up
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_AES_128_GCM_SHA256 = 0x1301,
}

#[derive(Debug, Clone)]
pub enum SupportGroup {
    // These are extensions supported from TLS1.0 onwards
    GROUP_SECP256R1 = 0x0017,
    GROUP_SECP384R1 = 0x0018,
    GROUP_SECP521R1 = 0x0019,
    GROUP_X25519 = 0x001d,
    GROUP_X448 = 0x001e,
}

#[derive(Debug, Clone)]
pub enum EcPointFormats {
    // These are extensions supported from TLS1.0 onwards
    EC_POINT_FORMAT_UNCOMPRESSED = 0x00,
    EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME = 0x01,
    EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2 = 0x02,
}

#[derive(Debug)]
pub struct Version {
    pub protocol: Protocol,
    pub ciphers: Vec<Cipher>,
    pub ext_support_groups: Option<Vec<SupportGroup>>,
    pub ext_ec_point_formats: Option<Vec<EcPointFormats>>,
}

impl Version {
    fn new(
        protocol: Protocol,
        ciphers: Vec<Cipher>,
        ext_support_groups: Option<Vec<SupportGroup>>,
        ext_ec_point_formats: Option<Vec<EcPointFormats>>,
    ) -> Version {
        Version { 
            protocol: protocol,
            ciphers: ciphers,  
            ext_support_groups: ext_support_groups,
            ext_ec_point_formats: ext_ec_point_formats,
        }
    }

    pub fn client_hello() {
        
    }

    pub fn server_hello_response() {

    }
}

pub struct TestSuite {
    pub versions: Vec<Version>
}
impl TestSuite {
    pub fn new() -> TestSuite {
        let ssl20 = Version::new(
            Protocol::SSLV20, 
            vec![
                Cipher::SSL2_RC4_128_WITH_MD5,
                Cipher::SSL2_RC4_128_EXPORT40_WITH_MD5,
                Cipher::SSL2_RC2_128_CBC_WITH_MD5,
                Cipher::SSL2_RC2_128_CBC_EXPORT40_WITH_MD5,
                Cipher::SSL2_IDEA_128_CBC_WITH_MD5,
                Cipher::SSL2_DES_64_CBC_WITH_MD5,
                Cipher::SSL2_DES_192_EDE3_CBC_WITH_MD5,
            ],
            None,
            None
        );
        let ciphers_ssl30_tls10_tls11 = vec![
            Cipher::TLS_RSA_WITH_NULL_MD5,
            Cipher::TLS_RSA_WITH_NULL_SHA,
            Cipher::TLS_RSA_EXPORT_WITH_RC4_40_MD5,
            Cipher::TLS_RSA_WITH_RC4_128_MD5,
            Cipher::TLS_RSA_WITH_RC4_128_SHA,
            Cipher::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
            Cipher::TLS_RSA_WITH_IDEA_CBC_SHA,
            Cipher::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
            Cipher::TLS_RSA_WITH_DES_CBC_SHA,
            Cipher::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_DH_DSS_WITH_DES_CBC_SHA,
            Cipher::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_DH_RSA_WITH_DES_CBC_SHA,
            Cipher::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
            Cipher::TLS_DHE_DSS_WITH_DES_CBC_SHA,
            Cipher::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
            Cipher::TLS_DHE_RSA_WITH_DES_CBC_SHA,
            Cipher::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5,
            Cipher::TLS_DH_ANON_WITH_RC4_128_MD5,
            Cipher::TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA,
            Cipher::TLS_DH_ANON_WITH_DES_CBC_SHA,
            Cipher::TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_RSA_WITH_AES_128_CBC_SHA,
            Cipher::TLS_DH_DSS_WITH_AES_128_CBC_SHA,
            Cipher::TLS_DH_RSA_WITH_AES_128_CBC_SHA,
            Cipher::TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            Cipher::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            Cipher::TLS_DH_ANON_WITH_AES_128_CBC_SHA,
            Cipher::TLS_RSA_WITH_AES_256_CBC_SHA,
            Cipher::TLS_DH_DSS_WITH_AES_256_CBC_SHA,
            Cipher::TLS_DH_RSA_WITH_AES_256_CBC_SHA,
            Cipher::TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
            Cipher::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            Cipher::TLS_DH_ANON_WITH_AES_256_CBC_SHA,
            Cipher::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
            Cipher::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
            Cipher::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
            Cipher::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
            Cipher::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
            Cipher::TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA,
            Cipher::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
            Cipher::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
            Cipher::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
            Cipher::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
            Cipher::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
            Cipher::TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA,
            Cipher::TLS_RSA_WITH_SEED_CBC_SHA,
            Cipher::TLS_DH_DSS_WITH_SEED_CBC_SHA,
            Cipher::TLS_DH_RSA_WITH_SEED_CBC_SHA,
            Cipher::TLS_DHE_DSS_WITH_SEED_CBC_SHA,
            Cipher::TLS_DHE_RSA_WITH_SEED_CBC_SHA,
            Cipher::TLS_DH_ANON_WITH_SEED_CBC_SHA,
            Cipher::TLS_ECDH_ECDSA_WITH_NULL_SHA,
            Cipher::TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
            Cipher::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
            Cipher::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
            Cipher::TLS_ECDHE_ECDSA_WITH_NULL_SHA,
            Cipher::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
            Cipher::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            Cipher::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            Cipher::TLS_ECDH_RSA_WITH_NULL_SHA,
            Cipher::TLS_ECDH_RSA_WITH_RC4_128_SHA,
            Cipher::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
            Cipher::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
            Cipher::TLS_ECDHE_RSA_WITH_NULL_SHA,
            Cipher::TLS_ECDHE_RSA_WITH_RC4_128_SHA,
            Cipher::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            Cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            Cipher::TLS_ECDH_ANON_WITH_NULL_SHA,
            Cipher::TLS_ECDH_ANON_WITH_RC4_128_SHA,
            Cipher::TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA,
            Cipher::TLS_ECDH_ANON_WITH_AES_128_CBC_SHA,
            Cipher::TLS_ECDH_ANON_WITH_AES_256_CBC_SHA,
        ];
        let ssl30 = Version::new(
            Protocol::SSLV30,
            ciphers_ssl30_tls10_tls11.clone(),
            None,
            None
        );
        let esg = vec![
            SupportGroup::GROUP_SECP256R1,
            SupportGroup::GROUP_SECP384R1,
            SupportGroup::GROUP_SECP521R1,
            SupportGroup::GROUP_X25519,
            SupportGroup::GROUP_X448,
        ];
        let epf = vec![
            EcPointFormats::EC_POINT_FORMAT_UNCOMPRESSED,
            EcPointFormats::EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME,
            EcPointFormats::EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2,
        ];

        let tls10 = Version::new(
            Protocol::TLSV10,
            ciphers_ssl30_tls10_tls11.clone(),
            Some(esg.clone()),
            Some(epf.clone()),
        );
    
        let tls11 = Version::new(
            Protocol::TLSV11,
            ciphers_ssl30_tls10_tls11.clone(),
            Some(esg.clone()),
            Some(epf.clone()),
        );
    
        let mut ciphers_tls12 = vec![
            Cipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            Cipher::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            Cipher::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
            Cipher::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
            Cipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            Cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            Cipher::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
            Cipher::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
            Cipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            Cipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            Cipher::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
            Cipher::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
            Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            Cipher::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
            Cipher::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
            Cipher::TLS_RSA_WITH_ARIA_128_GCM_SHA256,
            Cipher::TLS_RSA_WITH_ARIA_256_GCM_SHA384,
            Cipher::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
            Cipher::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
            Cipher::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
            Cipher::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
            Cipher::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
            Cipher::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
            Cipher::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
            Cipher::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
            Cipher::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
            Cipher::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
            Cipher::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            Cipher::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
            Cipher::TLS_RSA_WITH_AES_128_CCM,
            Cipher::TLS_RSA_WITH_AES_256_CCM,
            Cipher::TLS_DHE_RSA_WITH_AES_128_CCM,
            Cipher::TLS_DHE_RSA_WITH_AES_256_CCM,
            Cipher::TLS_RSA_WITH_AES_128_CCM_8,
            Cipher::TLS_RSA_WITH_AES_256_CCM_8,
            Cipher::TLS_DHE_RSA_WITH_AES_128_CCM_8,
            Cipher::TLS_DHE_RSA_WITH_AES_256_CCM_8,
            Cipher::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
            Cipher::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
            Cipher::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            Cipher::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
            Cipher::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            Cipher::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            Cipher::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ];
        ciphers_tls12.extend(ciphers_ssl30_tls10_tls11);
        
        let tls12 = Version::new(
            Protocol::TLSV12,
            ciphers_tls12,
            Some(esg.clone()),
            Some(epf.clone()),
        );
    
        TestSuite {
            versions: vec![ssl20, ssl30, tls10, tls11, tls12],
        }
    }
}
