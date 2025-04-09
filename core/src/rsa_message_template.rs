use std::fmt::Display;

use const_oid::{db::DB, ObjectIdentifier};
use der::{asn1::Null, Encode};
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

/// Helper to manually encode an ASN.1 Length
fn encode_asn1_length(len: usize) -> Vec<u8> {
    if let Ok(len_u8) = u8::try_from(len) {
        if len_u8 < 128 {
            // Short form
            vec![len_u8]
        } else {
            // Long form
            let len_bytes = len.to_be_bytes();
            // Find the first non-zero byte
            let num_non_zero = len_bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(len_bytes.len());
            let num_len_octets = len_bytes.len() - num_non_zero;
            let mut result = Vec::with_capacity(1 + num_len_octets);
            result.push(0x80 | num_len_octets as u8); // Length byte indicator
            result.extend_from_slice(&len_bytes[num_non_zero..]);
            result
        }
    } else {
        // Handle very large lengths if necessary, similar to long form
        panic!("Length too large for simple u8 conversion in this example"); // Or implement full handling
    }
}

/// Creates a PKCS#1 v1.5 formatted message for RSA verification
/// ... (rest of the doc comment) ...
pub fn create_pkcs1v15_message(digest_variant: Sha2Variant, key_size_bytes: usize) -> Vec<u8> {
    // Create zeroed digest of requested size
    let digest_size = digest_variant.get_size();
    let zeroed_digest = vec![0u8; digest_size];

    // --- Correctly build the DigestInfo structure ---

    // 1. Encode the OID correctly (Tag + Length + Value)
    let oid = digest_variant.get_oid();
    let encoded_oid = oid.to_der().expect("Failed to encode OID"); // Use der::Encode::to_vec

    // 2. Encode the NULL parameters correctly (Tag + Length)
    let encoded_null = Null.to_der().expect("Failed to encode NULL"); // Produces [0x05, 0x00]

    // 3. Build the AlgorithmIdentifier SEQUENCE content
    let alg_id_content = [encoded_oid, encoded_null].concat();

    // 4. Build the AlgorithmIdentifier SEQUENCE (Tag + Length + Content)
    let mut encoded_alg_id = Vec::new();
    encoded_alg_id.push(0x30); // SEQUENCE Tag
    encoded_alg_id.extend(encode_asn1_length(alg_id_content.len())); // Correct length encoding
    encoded_alg_id.extend_from_slice(&alg_id_content);

    // 5. Build the Digest OCTET STRING (Tag + Length + Content)
    let mut encoded_digest = Vec::new();
    encoded_digest.push(0x04); // OCTET STRING Tag
    encoded_digest.extend(encode_asn1_length(zeroed_digest.len())); // Correct length encoding
    encoded_digest.extend_from_slice(&zeroed_digest);

    // 6. Build the DigestInfo SEQUENCE content
    let digest_info_content = [encoded_alg_id, encoded_digest].concat();

    // 7. Build the final DigestInfo SEQUENCE (Tag + Length + Content)
    let mut digest_info = Vec::new(); // This is our final 'T'
    digest_info.push(0x30); // SEQUENCE Tag
    digest_info.extend(encode_asn1_length(digest_info_content.len())); // Correct length encoding
    digest_info.extend_from_slice(&digest_info_content);

    // --- Correct length calculation for DigestInfo ---
    // For SHA-256:
    // encoded_oid = 11 bytes (06 09 ...)
    // encoded_null = 2 bytes (05 00)
    // alg_id_content = 13 bytes
    // encoded_alg_id = 1 (tag) + 1 (len 0x0D) + 13 = 15 bytes (30 0D ...)
    // encoded_digest = 1 (tag) + 1 (len 0x20) + 32 = 34 bytes (04 20 ...)
    // digest_info_content = 15 + 34 = 49 bytes
    // digest_info = 1 (tag) + 1 (len 0x31) + 49 = 51 bytes (30 31 ...)
    // This matches the expected length.

    // --- Apply PKCS#1 v1.5 padding ---
    let t_len = digest_info.len(); // Use the length of the correctly encoded DigestInfo
    if key_size_bytes < t_len + 11 {
        // 3 bytes for 00 01 ... 00 + minimum 8 bytes FF
        panic!(
            "Key size {} bytes is too small for DigestInfo ({} bytes) and PKCS#1 v1.5 padding",
            key_size_bytes, t_len
        );
    }

    let padding_len = key_size_bytes - t_len - 3; // 3 bytes for 0x00, 0x01, 0x00 separator

    let mut padded_message = Vec::with_capacity(key_size_bytes);
    padded_message.push(0x00); // Leading zero
    padded_message.push(0x01); // Block type 1
    padded_message.extend(vec![0xFF; padding_len]); // FF padding
    padded_message.push(0x00); // Separator byte
    padded_message.extend_from_slice(&digest_info); // Add correctly encoded DigestInfo

    // Verify the final message is exactly the right size
    assert_eq!(
        padded_message.len(),
        key_size_bytes,
        "Internal error: Incorrect final padded message length. Expected {}, got {}",
        key_size_bytes,
        padded_message.len()
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

    #[test]
    fn test_sha256_4096_structure() {
        // Specifically check the structure for the case that failed before
        let key_size_bytes = 512;
        let digest_variant = Sha2Variant::Sha256;
        let msg = create_pkcs1v15_message(digest_variant, key_size_bytes);

        assert_eq!(msg.len(), key_size_bytes);
        assert_eq!(msg[0..2], [0x00, 0x01]); // Check header

        // Calculate expected DigestInfo length and padding length
        // As derived above, DigestInfo for SHA-256 is 51 bytes
        let t_len = 51;
        let padding_len = key_size_bytes - t_len - 3; // 512 - 51 - 3 = 458
        let separator_index = 2 + padding_len; // 2 + 458 = 460

        // Check padding block
        for i in 2..separator_index {
            assert_eq!(msg[i], 0xFF, "Padding byte at index {} is not FF", i);
        }

        // Check separator
        assert_eq!(
            msg[separator_index], 0x00,
            "Separator byte at index {} is not 00",
            separator_index
        );

        // Check DigestInfo prefix (first few bytes)
        // Expected: 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        let expected_prefix: Vec<u8> =
            hex::decode("3031300d060960864801650304020105000420").unwrap();
        assert_eq!(
            msg[separator_index + 1..separator_index + 1 + expected_prefix.len()],
            expected_prefix,
            "DigestInfo prefix mismatch"
        );

        // Check that the rest is zeroed digest
        let digest_start_index = separator_index + 1 + expected_prefix.len();
        let digest_size = digest_variant.get_size(); // 32
        assert_eq!(
            digest_start_index + digest_size,
            key_size_bytes,
            "Digest end index calculation mismatch"
        );
        for i in 0..digest_size {
            assert_eq!(
                msg[digest_start_index + i],
                0x00,
                "Digest byte at index {} is not 00",
                digest_start_index + i
            );
        }

        // Optional: Print the relevant part for manual verification
        // println!("Separator index: {}", separator_index);
        // println!("DigestInfo starts at: {}", separator_index + 1);
        // println!("DigestInfo Hex: {}", hex::encode(&msg[separator_index + 1..]));
        // Example expected DigestInfo hex for SHA256 with zero hash:
        // 3031300d0609608648016503040201050004200000000000000000000000000000000000000000000000000000000000000000
        let expected_digest_info_hex = "3031300d0609608648016503040201050004200000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            hex::encode(&msg[separator_index + 1..]),
            expected_digest_info_hex
        );
    }
}
