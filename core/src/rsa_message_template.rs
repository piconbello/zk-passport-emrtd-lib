use std::fmt::Display;

use const_oid::{db::DB, ObjectIdentifier};
use der::Encode;
use num_bigint::BigUint;
use serde::Serialize;
use serde_with::{serde_as, DisplayFromStr, Map};

const DIGEST_VARIANTS: &'static [Sha2Variant] = &[Sha2Variant::Sha256, Sha2Variant::Sha512];
const KEY_SIZES_BYTES: &'static [usize] = &[512, 256];

#[derive(Debug, Copy, Clone)]
pub enum Sha2Variant {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Sha2Variant {
    pub fn get_oid(&self) -> &'static ObjectIdentifier {
        match self {
            Sha2Variant::Sha224 => DB.by_name("id-sha224").unwrap(),
            Sha2Variant::Sha256 => DB.by_name("id-sha256").unwrap(),
            Sha2Variant::Sha384 => DB.by_name("id-sha384").unwrap(),
            Sha2Variant::Sha512 => DB.by_name("id-sha512").unwrap(),
        }
    }

    pub fn get_size(&self) -> usize {
        match self {
            Sha2Variant::Sha224 => 28,
            Sha2Variant::Sha256 => 32,
            Sha2Variant::Sha384 => 48,
            Sha2Variant::Sha512 => 64,
        }
    }

    pub fn get_name(&self) -> &'static str {
        match self {
            Sha2Variant::Sha224 => "SHA2-224",
            Sha2Variant::Sha256 => "SHA2-256",
            Sha2Variant::Sha384 => "SHA2-384",
            Sha2Variant::Sha512 => "SHA2-512",
        }
    }
}

/// Creates a PKCS#1 v1.5 formatted message for RSA verification
///
/// This function creates a properly formatted message according to PKCS#1 v1.5 standard,
/// with a zeroed digest of the specified hash algorithm. The message is padded to match
/// the RSA key size.
///
/// # Arguments
/// * `digest_variant` - The SHA2 hash algorithm variant to use
/// * `key_size_bytes` - The RSA key size in bytes (e.g., 512 for 4096-bit RSA)
///
/// # Returns
/// A struct containing the formatted message and the bit offset where the digest begins
pub fn create_pkcs1v15_message(digest_variant: Sha2Variant, key_size_bytes: usize) -> Vec<u8> {
    // Create zeroed digest of requested size
    let digest_size = digest_variant.get_size();
    let zeroed_digest = vec![0u8; digest_size];

    // Create the DigestInfo structure using ASN.1 DER encoding
    let digest_info = {
        // Get the OID for the hash algorithm
        let oid = digest_variant.get_oid();

        // Calculate all lengths in advance for proper ASN.1 DER encoding
        // NULL is always 2 bytes (0x05 tag + 0x00 length)
        let null_len = 2;

        // AlgorithmIdentifier = SEQUENCE(OID + NULL)
        let oid_encoded_len: u32 = oid
            .encoded_len()
            .expect("OID encoding should never fail")
            .into();
        let alg_id_content_len = oid_encoded_len as usize + null_len;
        let alg_id_len = 1 + 1 + alg_id_content_len; // 0x30 tag + length byte + content

        // OctetString = 0x04 tag + length byte + digest value
        let octet_string_len = 1 + 1 + digest_size;

        // DigestInfo = SEQUENCE(AlgorithmIdentifier + OctetString)
        let digest_info_content_len = alg_id_len + octet_string_len;
        let digest_info_len = 1 + 1 + digest_info_content_len; // 0x30 tag + length byte + content

        // Allocate the exact size needed for DigestInfo
        let mut result = Vec::with_capacity(digest_info_len);

        // SEQUENCE for DigestInfo (0x30 = ASN.1 SEQUENCE tag)
        result.push(0x30);
        result.push(digest_info_content_len as u8);

        // SEQUENCE for AlgorithmIdentifier
        result.push(0x30);
        result.push(alg_id_content_len as u8);

        // OID for algorithm
        result.extend_from_slice(oid.as_bytes());

        // NULL for parameters (0x05 = ASN.1 NULL tag)
        result.push(0x05);
        result.push(0x00);

        // OCTET STRING for digest (0x04 = ASN.1 OCTET STRING tag)
        result.push(0x04);
        result.push(digest_size as u8);

        // The digest starts here - remember this position for calculating offset
        result.extend_from_slice(&zeroed_digest);

        result
    };

    // Apply PKCS#1 v1.5 padding
    let mut padded_message = Vec::with_capacity(key_size_bytes);
    // 0x00 and 0x01 are the PKCS#1 v1.5 block type 1 header
    padded_message.push(0x00); // Leading zero
    padded_message.push(0x01); // Block type 1 for private key operations

    // Padding string of 0xFF bytes (required for block type 1)
    let padding_len = key_size_bytes - digest_info.len() - 3; // 3 bytes for 0x00, 0x01, 0x00
    padded_message.extend(vec![0xFF; padding_len]);

    padded_message.push(0x00); // Separator byte between padding and data

    // Add DigestInfo
    padded_message.extend_from_slice(&digest_info);

    // Verify the final message is exactly the right size
    assert_eq!(
        padded_message.len(),
        key_size_bytes,
        "Incorrect message length"
    );

    padded_message
}

pub fn pkcs1v15_message_to_limbs(padded_message: &[u8]) -> Vec<BigUint> {
    // Calculate total bits in the message
    let total_bits = padded_message.len() * 8;

    // Extract limbs in little-endian order
    let expected_limbs = (total_bits + 115) / 116;
    let mut limbs = Vec::with_capacity(expected_limbs);
    let mask = (BigUint::from(1u32) << 116) - BigUint::from(1u32);

    let mut message_bigint = BigUint::from_bytes_be(padded_message);
    for _ in 0..expected_limbs {
        limbs.push(&message_bigint & &mask);
        message_bigint >>= 116;
    }

    limbs
}

#[derive(Debug)]
pub struct Pair {
    digest_algo: Sha2Variant,
    key_size_bytes: usize,
}

impl Display for Pair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{},{}",
            self.digest_algo.get_name(),
            self.key_size_bytes * 8
        )
    }
}

#[serde_as]
#[derive(Debug, Serialize)]
pub struct RsaMessageTemplate {
    #[serde_as(as = "Vec<DisplayFromStr>")]
    limbs: Vec<BigUint>,
}

impl RsaMessageTemplate {
    pub fn new(digest_variant: Sha2Variant, key_size_bytes: usize) -> Self {
        let message = create_pkcs1v15_message(digest_variant, key_size_bytes);
        let limbs = pkcs1v15_message_to_limbs(&message);
        Self { limbs }
    }
}

#[serde_as]
#[derive(Debug, Serialize)]
pub struct RsaMessageTemplates {
    #[serde_as(as = "Map<DisplayFromStr, _>")]
    rsa_message_templates: Vec<(Pair, RsaMessageTemplate)>,
}

impl RsaMessageTemplates {
    pub fn generate() -> Self {
        let mut templs: Vec<_> = Vec::with_capacity(DIGEST_VARIANTS.len() * KEY_SIZES_BYTES.len());
        for &v in DIGEST_VARIANTS {
            for &s in KEY_SIZES_BYTES {
                let pair = Pair {
                    digest_algo: v,
                    key_size_bytes: s,
                };
                let templ = RsaMessageTemplate::new(v, s);
                templs.push((pair, templ));
            }
        }
        Self {
            rsa_message_templates: templs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs1v15_message_sizes() {
        // Test for 2048-bit RSA key with SHA-256
        let msg_2048_sha256 = create_pkcs1v15_message(Sha2Variant::Sha256, 256);
        assert_eq!(msg_2048_sha256.len(), 256);

        // Test for 4096-bit RSA key with SHA-256
        let msg_4096_sha256 = create_pkcs1v15_message(Sha2Variant::Sha256, 512);
        assert_eq!(msg_4096_sha256.len(), 512);

        // Test for 4096-bit RSA key with SHA-512
        let msg_4096_sha512 = create_pkcs1v15_message(Sha2Variant::Sha512, 512);
        assert_eq!(msg_4096_sha512.len(), 512);
    }

    #[test]
    fn test_digest_info_structure() {
        // Verify the DigestInfo structure is correctly formatted for SHA-256
        let msg = create_pkcs1v15_message(Sha2Variant::Sha256, 256);

        // Find the DigestInfo by looking for the SEQUENCE tag after padding
        let mut digest_info_start = 0;
        for i in 3..msg.len() {
            if msg[i - 1] == 0x00 && msg[i] == 0x30 {
                digest_info_start = i;
                break;
            }
        }

        assert_ne!(digest_info_start, 0, "DigestInfo not found in message");

        // Check the DigestInfo structure
        assert_eq!(
            msg[digest_info_start], 0x30,
            "DigestInfo should start with SEQUENCE tag"
        );

        // Check that the OID is present
        let sha256_oid_bytes = DB.by_name("id-sha256").unwrap().as_bytes();
        let mut found_oid = false;

        for i in digest_info_start..msg.len() - sha256_oid_bytes.len() {
            if &msg[i..i + sha256_oid_bytes.len()] == sha256_oid_bytes {
                found_oid = true;
                break;
            }
        }

        assert!(found_oid, "SHA-256 OID not found in DigestInfo");
    }

    #[test]
    fn test_digest_position() {
        // Test for 4096-bit RSA key with SHA-256
        let msg = create_pkcs1v15_message(Sha2Variant::Sha256, 512);

        // Find the digest position by looking for the OctetString tag (0x04)
        // followed by length byte (0x20 = 32 for SHA-256) followed by zeros
        let mut digest_pos = 0;
        for i in 0..msg.len() - 33 {
            // Need at least 33 bytes (tag + length + digest)
            if msg[i] == 0x04 && msg[i + 1] == 0x20 && msg[i + 2] == 0x00 {
                digest_pos = i + 2; // Position of first digest byte
                break;
            }
        }

        assert_ne!(digest_pos, 0, "Digest position not found in message");

        // Check that we have 32 zero bytes (SHA-256 digest size) at the position
        for i in 0..32 {
            assert_eq!(
                msg[digest_pos + i],
                0,
                "Expected zero byte at digest position {}",
                digest_pos + i
            );
        }

        // Verify the tag and length
        assert_eq!(
            msg[digest_pos - 2],
            0x04,
            "Expected OCTET STRING tag before digest"
        );
        assert_eq!(
            msg[digest_pos - 1],
            32,
            "Expected length byte to be 32 for SHA-256"
        );
    }
}
