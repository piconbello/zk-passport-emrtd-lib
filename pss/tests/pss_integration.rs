//! Integration tests for PSS padding implementation.
//! Tests encoding/verification with various message sizes and error conditions.

use color_eyre::Result;
use digest::{Digest, DynDigest};
use pss::pss::{div_ceil, emsa_pss_encode, emsa_pss_verify};
use sha2::Sha256;

// Test configuration
const KEY_BITS: usize = 2048;
const HASH_OUTPUT_LEN: usize = 32; // SHA-256
const SALT_LEN: usize = HASH_OUTPUT_LEN;
const EM_BITS: usize = KEY_BITS - 1;

#[test]
fn test_encode_verify_roundtrip() -> Result<()> {
    // Fixed salt for deterministic tests
    let fixed_salt = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];

    let messages: [&[u8]; 4] = [
        b"", // Empty message
        b"short message",
        b"This is a slightly longer message used for testing.",
        &[0u8; 1024], // A large binary message
    ];

    for msg in messages {
        // Hash the message
        let mut hash_instance = Sha256::new();
        DynDigest::update(&mut hash_instance, msg);
        let m_hash = DynDigest::finalize_reset(&mut hash_instance);
        assert_eq!(m_hash.len(), HASH_OUTPUT_LEN, "Hash output length mismatch");

        // Encode with PSS
        let mut encode_hash = Sha256::new();
        let em = emsa_pss_encode(&m_hash, EM_BITS, &fixed_salt, &mut encode_hash)?;

        // Check encoded message length
        let expected_em_len = div_ceil(EM_BITS, 8);
        assert_eq!(em.len(), expected_em_len, "Encoded message length mismatch");

        // Verify the encoded message (success case)
        let mut em_verify = em.clone();
        let mut verify_hash = Sha256::new();
        emsa_pss_verify(
            &m_hash,
            &mut em_verify,
            SALT_LEN,
            &mut verify_hash,
            KEY_BITS,
        )?;
    }

    Ok(())
}

#[test]
fn test_tampered_em_fails() -> Result<()> {
    let msg = b"Test message for tampering";
    let fixed_salt = [0xAA; SALT_LEN]; // Different salt from other tests

    // Hash the message
    let mut hash_instance = Sha256::new();
    DynDigest::update(&mut hash_instance, msg);
    let m_hash = DynDigest::finalize_reset(&mut hash_instance);

    // Encode with PSS
    let mut encode_hash = Sha256::new();
    let em = emsa_pss_encode(&m_hash, EM_BITS, &fixed_salt, &mut encode_hash)?;

    // Tamper with different bytes and check that verification fails
    let tampering_positions = [0, em.len() / 4, em.len() / 2, em.len() - 2, em.len() - 1];

    for &pos in &tampering_positions {
        let mut tampered_em = em.clone();
        tampered_em[pos] ^= 0xAA; // Flip some bits

        let mut verify_hash = Sha256::new();
        let result = emsa_pss_verify(
            &m_hash,
            &mut tampered_em,
            SALT_LEN,
            &mut verify_hash,
            KEY_BITS,
        );

        assert!(
            result.is_err(),
            "Verification should fail for tampering at position {}",
            pos
        );
    }

    Ok(())
}

#[test]
fn test_wrong_message_hash_fails() -> Result<()> {
    let msg = b"Original message";
    let wrong_msg = b"Different message";
    let fixed_salt = [0xBB; SALT_LEN]; // Different salt from other tests

    // Hash the original message
    let mut hash_instance = Sha256::new();
    DynDigest::update(&mut hash_instance, msg);
    let m_hash = DynDigest::finalize_reset(&mut hash_instance);

    // Hash the wrong message
    let mut wrong_hash_instance = Sha256::new();
    DynDigest::update(&mut wrong_hash_instance, wrong_msg);
    let wrong_m_hash = DynDigest::finalize_reset(&mut wrong_hash_instance);

    // Encode with PSS using original hash
    let mut encode_hash = Sha256::new();
    let em = emsa_pss_encode(&m_hash, EM_BITS, &fixed_salt, &mut encode_hash)?;

    // Verify with wrong hash
    let mut em_verify = em.clone();
    let mut verify_hash = Sha256::new();
    let result = emsa_pss_verify(
        &wrong_m_hash,
        &mut em_verify,
        SALT_LEN,
        &mut verify_hash,
        KEY_BITS,
    );

    assert!(
        result.is_err(),
        "Verification should fail with wrong message hash"
    );

    Ok(())
}

#[test]
fn test_wrong_salt_length_fails() -> Result<()> {
    let msg = b"Message for salt length test";
    let fixed_salt = [0xCC; SALT_LEN];

    // Hash the message
    let mut hash_instance = Sha256::new();
    DynDigest::update(&mut hash_instance, msg);
    let m_hash = DynDigest::finalize_reset(&mut hash_instance);

    // Encode with PSS
    let mut encode_hash = Sha256::new();
    let em = emsa_pss_encode(&m_hash, EM_BITS, &fixed_salt, &mut encode_hash)?;

    // Try different salt lengths
    let salt_len_variants = [SALT_LEN - 1, SALT_LEN + 1];

    for &wrong_salt_len in &salt_len_variants {
        if wrong_salt_len == 0 || em.len() < HASH_OUTPUT_LEN + wrong_salt_len + 2 {
            // Skip invalid salt lengths that would cause parameter errors
            continue;
        }

        let mut em_verify = em.clone();
        let mut verify_hash = Sha256::new();
        let result = emsa_pss_verify(
            &m_hash,
            &mut em_verify,
            wrong_salt_len,
            &mut verify_hash,
            KEY_BITS,
        );

        assert!(
            result.is_err(),
            "Verification should fail with wrong salt length {}",
            wrong_salt_len
        );
    }

    Ok(())
}
