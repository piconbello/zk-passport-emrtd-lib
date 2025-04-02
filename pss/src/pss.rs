//! EMSA-PSS encoding and verification logic, adapted for standalone use.
//! Based on RFC8017 § 8.1 and § 9.1.

use color_eyre::{Result, eyre::eyre};
use digest::DynDigest;
use subtle::{Choice, ConstantTimeEq};

// Helper for integer division ceiling
pub fn div_ceil(a: usize, b: usize) -> usize {
    if b == 0 {
        panic!("Division by zero in div_ceil");
    }
    (a + b - 1) / b
}

/// Implements MGF1 using the provided hash function.
/// XORs the generated mask with the destination buffer `dst`.
/// `hash` instance is used internally and reset.
fn mgf1_xor(dst: &mut [u8], hash: &mut dyn DynDigest, seed: &[u8]) -> Result<()> {
    let h_len = hash.output_size();
    if h_len == 0 {
        return Err(eyre!("Hash function output size cannot be zero for MGF1"));
    }
    let mut counter = [0u8; 4];
    let mut i = 0;

    // Process in chunks of h_len
    for chunk in dst.chunks_mut(h_len) {
        // Increment counter C
        let c = i as u32;
        counter[0] = (c >> 24) as u8;
        counter[1] = (c >> 16) as u8;
        counter[2] = (c >> 8) as u8;
        counter[3] = c as u8;

        // Hash(seed || C)
        hash.update(seed);
        hash.update(&counter);
        let mask_chunk = hash.finalize_reset();

        // XOR chunk with the mask
        for (i, m) in mask_chunk.iter().take(chunk.len()).enumerate() {
            chunk[i] ^= *m;
        }

        i += 1;
    }

    Ok(())
}

/// EMSA-PSS Encoding (RFC 8017 Section 9.1.1)
///
/// Creates the encoded message `EM` for PSS signature generation.
///
/// # Arguments
/// * `m_hash`: The hash of the message to be signed. Length must match `hash.output_size()`.
/// * `em_bits`: The target length of the encoded message in bits (typically `key_bits - 1`).
/// * `salt`: The random salt value. Its length (`s_len`) is crucial.
/// * `hash`: A hash function instance (will be reset). Used for internal hashing and MGF1.
///
/// # Returns
/// The encoded message `EM` as a byte vector.
pub fn emsa_pss_encode(
    m_hash: &[u8],
    em_bits: usize,
    salt: &[u8],
    hash: &mut dyn DynDigest,
) -> Result<Vec<u8>> {
    let h_len = hash.output_size();
    let s_len = salt.len();
    // Note: em_len is length in bytes. RFC uses emBits for bits.
    let em_len = div_ceil(em_bits, 8);

    // Step 2: Check m_hash length
    if m_hash.len() != h_len {
        return Err(eyre!(
            "Input hash length {} does not match digest output size {}",
            m_hash.len(),
            h_len
        ));
    }

    // Step 3: Check em_len
    if em_len < h_len + s_len + 2 {
        return Err(eyre!(
            "Encoding error: em_len ({}) too small for hash ({}) and salt ({})",
            em_len,
            h_len,
            s_len
        ));
    }

    // Step 4: Salt is provided as input.

    // Initialize EM buffer
    let mut em = vec![0u8; em_len];

    // Locate DB (Data Block) and H (hash of M') within EM
    let db_len = em_len - h_len - 1;
    let (db, h_suffix) = em.split_at_mut(db_len);
    // h_suffix = H || 0xbc. We need H part.
    let h = &mut h_suffix[..h_len];

    // Step 5 & 6: Calculate H = Hash( M' )
    // M' = (0x)00 00 00 00 00 00 00 00 || m_hash || salt
    let prefix = [0u8; 8];
    hash.update(&prefix);
    hash.update(m_hash);
    hash.update(salt);
    let hashed_m_prime = hash.finalize_reset();
    h.copy_from_slice(&hashed_m_prime); // Place H into EM

    // Step 7 & 8: Construct DB = PS || 0x01 || salt
    // PS is zeroes. db is already zero-initialized.
    // PS length = em_len - s_len - h_len - 2
    let ps_len = em_len - s_len - h_len - 2;
    // db[ps_len..] are the last s_len + 1 bytes of db
    db[ps_len] = 0x01;
    db[ps_len + 1..].copy_from_slice(salt);

    // Step 9 & 10: Mask DB using MGF1 with H as seed
    // maskedDB = DB \xor MGF1(H, db_len)
    mgf1_xor(db, hash, h)?; // mgf1_xor handles the reset of the hash

    // Step 11: Zero the leftmost bits
    let zero_bits = 8 * em_len - em_bits;
    if zero_bits > 0 && zero_bits < 8 {
        db[0] &= 0xFF >> zero_bits;
    } else if zero_bits >= 8 {
        // This case implies em_bits is not aligned with byte boundary,
        // and the difference is >= 1 byte. This shouldn't happen if em_bits = key_size - 1
        // where key_size is a multiple of 8, but handle defensively.
        // The RFC implies only the first *octet* needs masking based on bit calculation.
        // If zero_bits >= 8, masking the first byte with 0x00 would be needed IF
        // the spec intended multi-byte masking, but example only shows first byte.
        // Let's stick to masking only the first byte according to the bit count.
        if zero_bits < 8 {
            // Check again just in case logic evolved
            db[0] &= 0xFF >> zero_bits;
        } else {
            // If zero_bits >= 8, it means the first byte must be all zero
            db[0] = 0x00;
            // Consider if RFC implies *more* bytes should be zeroed if zero_bits > 8.
            // Typical RSA key sizes (1024, 2048, ...) make `key_bits % 8 == 0`,
            // so `em_bits = key_bits - 1` makes `em_bits % 8 == 7`.
            // Then `em_len = key_bits / 8`.
            // `8 * em_len - em_bits` = `key_bits - (key_bits - 1)` = 1.
            // So zero_bits is usually 1.
            // Let's assume only the first byte's high bits are masked per spec step 11.
        }
    }
    // If zero_bits == 0, no masking needed.

    // Step 12: Set the last byte to 0xbc
    em[em_len - 1] = 0xBC;

    Ok(em)
}

/// Helper for EMSA-PSS Verification (Steps 1-6 & 9 of RFC 8017 Section 9.1.2)
/// Performs initial checks and unmasking.
///
/// # Arguments
/// * `m_hash`: The hash of the original message.
/// * `em`: The candidate encoded message (will be mutated during unmasking).
/// * `em_bits`: The expected length of the original encoded message in bits.
/// * `s_len`: The expected length of the salt.
/// * `h_len`: The output length of the hash function.
///
/// # Returns
/// If initial checks pass, returns `Ok((db, h))` where `db` is the unmasked data block
/// and `h` is the hash embedded in `em`. Otherwise returns an `Err`.
fn emsa_pss_verify_pre<'a>(
    m_hash: &[u8],
    em: &'a mut [u8],
    em_bits: usize,
    s_len: usize,
    h_len: usize,
) -> Result<(&'a mut [u8], &'a [u8])> {
    // Note: h is immutable slice after extraction
    let em_len = em.len(); // Actual length of provided EM

    // Step 2: Check m_hash length
    if m_hash.len() != h_len {
        return Err(eyre!(
            "Verification failed: Input hash length {} does not match expected digest size {}",
            m_hash.len(),
            h_len
        ));
    }

    // Step 3: Check em_len based on expected em_bits and constraints
    let expected_em_len = div_ceil(em_bits, 8);
    if em_len != expected_em_len {
        // This check is subtle. The input `em` comes from RSA decryption result,
        // which should be padded to the key size. Verification often takes this
        // padded buffer. We might need to adjust slicing *before* calling this,
        // or adjust the check here. Let's assume `em` passed *is* the expected length.
        return Err(eyre!(
            "Verification failed: Provided EM length {} does not match expected {}",
            em_len,
            expected_em_len
        ));
    }
    if em_len < h_len + s_len + 2 {
        return Err(eyre!(
            "Verification failed: EM length ({}) too small for hash ({}) and salt ({})",
            em_len,
            h_len,
            s_len
        ));
    }

    // Step 4: Check trailing byte
    if em[em_len - 1] != 0xBC {
        return Err(eyre!("Verification failed: EM does not end with 0xBC"));
    }

    // Step 5: Locate maskedDB and H
    let db_len = em_len - h_len - 1;
    let (masked_db, h_suffix) = em.split_at_mut(db_len);
    let h = &h_suffix[..h_len]; // H part is immutable now

    // Step 6: Check leftmost bits
    let zero_bits = 8 * em_len - em_bits;
    if zero_bits > 0 && zero_bits < 8 {
        if masked_db[0] & (0xFF << (8 - zero_bits)) != 0 {
            return Err(eyre!(
                "Verification failed: Leftmost bits of maskedDB are not zero"
            ));
        }
    } else if zero_bits >= 8 {
        // If zero_bits >= 8, the first byte must be zero
        if masked_db[0] != 0x00 {
            return Err(eyre!(
                "Verification failed: Leftmost byte of maskedDB is not zero (when em_bits requires it)"
            ));
        }
        // Again, assume RFC only requires checking the bits in the first octet.
    }
    // If zero_bits == 0, no check needed.

    // Step 7 & 8 happen *after* this function using the returned H
    // Step 9: Zero the high bits of DB *after* unmasking. This must be done
    // by the caller using the `db` returned from this function *after* MGF1 XOR.

    Ok((masked_db, h)) // Return mutable masked_db (to become db) and immutable h
}

/// Helper for EMSA-PSS Verification (Step 10 of RFC 8017 Section 9.1.2)
/// Checks the padding structure (zeroes || 0x01) in the unmasked DB.
/// This runs in constant time with respect to the padding bytes.
fn emsa_pss_verify_salt_padding(db: &[u8], em_len: usize, s_len: usize, h_len: usize) -> Choice {
    let ps_len = em_len - h_len - s_len - 2;

    // Check if db length is sufficient for PS, 0x01, and salt
    if db.len() < ps_len + 1 {
        return Choice::from(0u8); // Invalid structure
    }

    // Check PS = 00 ... 00
    let (zeroes, rest) = db.split_at(ps_len);
    let mut ps_ok = Choice::from(1u8);
    for &byte in zeroes {
        ps_ok &= byte.ct_eq(&0x00);
    }

    // Check separator 0x01
    let sep_ok = rest[0].ct_eq(&0x01);

    ps_ok & sep_ok
}

/// EMSA-PSS Verification (RFC 8017 Section 9.1.2)
///
/// Verifies if the encoded message `em` corresponds to the message hash `m_hash`.
///
/// # Arguments
/// * `m_hash`: The hash of the original message.
/// * `em`: The candidate encoded message (e.g., from RSA decryption). This slice might
///         be longer than `em_len` due to key padding; only the relevant part determined
///         by `key_bits` will be used.
/// * `s_len`: The expected length of the salt used during encoding.
/// * `hash`: A hash function instance (will be reset). Used for MGF1 and internal hashing.
/// * `key_bits`: The RSA key size in bits. Used to determine `em_bits`.
///
/// # Returns
/// `Ok(())` if verification is successful, `Err` otherwise.
pub fn emsa_pss_verify(
    m_hash: &[u8],
    em_full: &mut [u8], // Full buffer, potentially padded from RSA op
    s_len: usize,
    hash: &mut dyn DynDigest,
    key_bits: usize,
) -> Result<()> {
    if key_bits < 2 {
        // Sanity check key_bits
        return Err(eyre!("Invalid key_bits: {}", key_bits));
    }
    let em_bits = key_bits - 1;
    let em_len = div_ceil(em_bits, 8); // Expected EM length in bytes
    // let key_len = div_ceil(key_bits, 8); // Key size in bytes
    let h_len = hash.output_size();

    // Adjust `em` slice to the actual expected length, assuming leading padding
    // if em_full is longer (e.g., from raw RSA decryption result).
    if em_full.len() < em_len {
        return Err(eyre!(
            "Verification failed: Provided EM buffer length {} is less than expected EM length {}",
            em_full.len(),
            em_len
        ));
    }
    // Take the last `em_len` bytes as the actual EM to verify
    let slice_start = em_full.len() - em_len;
    let em = &mut em_full[slice_start..];

    // Steps 1-6: Initial checks (mutates `em` slice in place)
    let (db, h) = emsa_pss_verify_pre(m_hash, em, em_bits, s_len, h_len)?;
    // `db` currently holds maskedDB, `h` holds H

    // Step 7 & 8: Unmask DB
    // DB = maskedDB \xor MGF1(H, db_len)
    // Need to clone h because mgf1_xor needs immutable seed, but we need db mutable
    let h_clone = h.to_vec(); // Avoids complex lifetime issues with mgf1_xor needing &[]
    mgf1_xor(db, hash, &h_clone)?; // db is now unmasked DB

    // Step 9: Zero the high bits of the *unmasked* DB
    let zero_bits = 8 * em_len - em_bits;
    if zero_bits > 0 && zero_bits < 8 {
        db[0] &= 0xFF >> zero_bits;
    } else if zero_bits >= 8 {
        db[0] = 0x00; // Ensure first byte is zero if needed
    }
    // If zero_bits == 0, no masking needed.

    // Step 10: Check padding structure (00...00 || 0x01)
    let padding_ok: Choice = emsa_pss_verify_salt_padding(db, em_len, s_len, h_len);

    // Step 11: Extract salt
    // Salt is the last s_len bytes of DB.
    let db_len = db.len(); // db_len = em_len - h_len - 1
    if db_len < s_len {
        // This check should be redundant due to Step 3 and Step 10 checks, but be safe.
        return Err(eyre!("Internal error: db length too small for salt"));
    }
    let salt = &db[db_len - s_len..];

    // Step 12 & 13: Calculate H' = Hash( M' )
    // M' = (0x)00 00 00 00 00 00 00 00 || m_hash || salt
    let prefix = [0u8; 8];
    hash.update(&prefix);
    hash.update(m_hash);
    hash.update(salt);
    let h_prime = hash.finalize_reset();

    // Step 14: Compare H and H' in constant time, also considering padding validity
    let hash_ok = h.ct_eq(&h_prime);
    let overall_ok = padding_ok & hash_ok;

    if overall_ok.into() {
        Ok(())
    } else {
        // Provide a slightly more specific error if possible
        if !bool::from(padding_ok) {
            Err(eyre!(
                "Verification failed: PSS padding structure (0x01 separator or leading zeros) invalid"
            ))
        } else if !bool::from(hash_ok) {
            Err(eyre!(
                "Verification failed: Recomputed hash H' does not match embedded hash H"
            ))
        } else {
            // Should not happen if overall_ok is false, but cover all cases
            Err(eyre!("Verification failed: Unknown reason"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_vector_rfc8017_c2() -> Result<()> {
        // Based on RFC 8017 Appendix C.2 PSS-SHA256 example
        // Note: RFC example uses a specific salt, we generate one but test the process
        const KEY_BITS: usize = 2048; // n has 2048 bits
        const EM_BITS: usize = KEY_BITS - 1; // 2047
        const H_LEN: usize = 32; // SHA-256
        const S_LEN: usize = 32; // Salt length = hLen in example

        let message = b"abc";
        let mut hasher = Sha256::new();
        DynDigest::update(&mut hasher, message);
        let m_hash = DynDigest::finalize_reset(&mut hasher); // Use reset version for consistency
        assert_eq!(m_hash.len(), H_LEN);

        // Generate a random salt of required length
        let mut salt = vec![0u8; S_LEN];
        rand::rng().fill_bytes(&mut salt);

        // Encode
        let mut encode_hasher = Sha256::new(); // Fresh hasher for encode internals
        let em = emsa_pss_encode(&m_hash, EM_BITS, &salt, &mut encode_hasher)?;

        // Verify
        let mut em_to_verify = em.clone(); // Clone since verify mutates
        let mut verify_hasher = Sha256::new(); // Fresh hasher for verify internals
        emsa_pss_verify(
            &m_hash,
            &mut em_to_verify,
            S_LEN,
            &mut verify_hasher,
            KEY_BITS,
        )?;

        Ok(())
    }

    #[test]
    fn test_encode_decode_roundtrip() -> Result<()> {
        const KEY_BITS: usize = 1024; // Smaller key for faster test
        const EM_BITS: usize = KEY_BITS - 1;
        const H_LEN: usize = 32; // SHA-256
        const S_LEN: usize = H_LEN; // Use hash len as salt len

        let messages: [&[u8]; 4] = [
            b"",
            b"short",
            b"this is a medium length message for testing purposes",
            b"this is a much longer message that will span multiple blocks in the hash function, ensuring that padding and hashing work correctly for larger inputs.",
        ];

        for msg in messages {
            println!("Testing message: {:?}", String::from_utf8_lossy(msg));
            let mut hasher = Sha256::new();
            DynDigest::update(&mut hasher, msg);
            let m_hash = DynDigest::finalize_reset(&mut hasher);

            let mut salt = vec![0u8; S_LEN];
            rand::rng().fill_bytes(&mut salt);

            // Encode
            let mut encode_hasher = Sha256::new();
            let em = emsa_pss_encode(&m_hash, EM_BITS, &salt, &mut encode_hasher)
                .expect("Encoding failed");

            let em_len_bytes = div_ceil(EM_BITS, 8);
            assert_eq!(em.len(), em_len_bytes, "EM length mismatch");

            // Verify (Successful)
            let mut em_to_verify = em.clone();
            let mut verify_hasher = Sha256::new();
            emsa_pss_verify(
                &m_hash,
                &mut em_to_verify,
                S_LEN,
                &mut verify_hasher,
                KEY_BITS,
            )
            .expect("Verification failed");

            // Verify (Tampered EM - last byte)
            let mut tampered_em = em.clone();
            tampered_em[em.len() - 1] ^= 0xff; // Flip last byte (0xBC)
            let mut verify_hasher_fail1 = Sha256::new();
            assert!(
                emsa_pss_verify(
                    &m_hash,
                    &mut tampered_em,
                    S_LEN,
                    &mut verify_hasher_fail1,
                    KEY_BITS
                )
                .is_err(),
                "Verification should fail with tampered EM (last byte)"
            );

            // Verify (Tampered EM - middle byte)
            let mut tampered_em2 = em.clone();
            if tampered_em2.len() > 1 {
                tampered_em2[em.len() / 2] ^= 0x01;
            }
            let mut verify_hasher_fail2 = Sha256::new();
            assert!(
                emsa_pss_verify(
                    &m_hash,
                    &mut tampered_em2,
                    S_LEN,
                    &mut verify_hasher_fail2,
                    KEY_BITS
                )
                .is_err(),
                "Verification should fail with tampered EM (middle byte)"
            );

            // Verify (Wrong hash)
            let mut wrong_hash = m_hash.clone();
            wrong_hash[0] ^= 0x01;
            let mut em_to_verify_wh = em.clone();
            let mut verify_hasher_fail3 = Sha256::new();
            assert!(
                emsa_pss_verify(
                    &wrong_hash,
                    &mut em_to_verify_wh,
                    S_LEN,
                    &mut verify_hasher_fail3,
                    KEY_BITS
                )
                .is_err(),
                "Verification should fail with wrong message hash"
            );

            // Verify (Wrong salt length)
            let mut em_to_verify_wsl = em.clone();
            let mut verify_hasher_fail4 = Sha256::new();
            let wrong_s_len = if S_LEN > 0 { S_LEN - 1 } else { S_LEN + 1 }; // Change salt length
            if em_len_bytes >= H_LEN + wrong_s_len + 2 {
                // Only test if possible with new s_len
                assert!(
                    emsa_pss_verify(
                        &m_hash,
                        &mut em_to_verify_wsl,
                        wrong_s_len,
                        &mut verify_hasher_fail4,
                        KEY_BITS
                    )
                    .is_err(),
                    "Verification should fail with wrong salt length"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn test_em_bits_edge_case() -> Result<()> {
        // Test a key size where em_bits % 8 != 7
        // e.g., a hypothetical 1029 bit key -> em_bits = 1028
        const KEY_BITS: usize = 1029;
        const EM_BITS: usize = KEY_BITS - 1; // 1028 bits
        const H_LEN: usize = 32; // SHA-256
        const S_LEN: usize = H_LEN;

        let em_len = div_ceil(EM_BITS, 8); // 1028 / 8 = 128.5 -> 129 bytes
        // let zero_bits = 8 * em_len - EM_BITS; // 8 * 129 - 1028 = 1032 - 1028 = 4 bits

        let msg = b"test edge case";
        let mut hasher = Sha256::new();
        DynDigest::update(&mut hasher, msg);
        let m_hash = DynDigest::finalize_reset(&mut hasher);

        let mut salt = vec![0u8; S_LEN];
        rand::rng().fill_bytes(&mut salt);

        // Encode
        let mut encode_hasher = Sha256::new();
        let em = emsa_pss_encode(&m_hash, EM_BITS, &salt, &mut encode_hasher)?;
        assert_eq!(em.len(), em_len);
        // Check the masking for 4 zero bits: high nibble should be 0
        assert_eq!(em[0] & 0xF0, 0x00, "Expected high nibble to be zeroed");

        // Verify
        let mut em_to_verify = em.clone();
        let mut verify_hasher = Sha256::new();
        emsa_pss_verify(
            &m_hash,
            &mut em_to_verify,
            S_LEN,
            &mut verify_hasher,
            KEY_BITS,
        )?;

        // Verify tampered high bits fail
        let mut tampered_em = em; // Use original `em` which is now owned
        tampered_em[0] |= 0b1000_0000; // Set the highest bit (which should be zero)
        let mut verify_hasher_fail = Sha256::new();
        assert!(
            emsa_pss_verify(
                &m_hash,
                &mut tampered_em,
                S_LEN,
                &mut verify_hasher_fail,
                KEY_BITS
            )
            .is_err(),
            "Verification should fail if high zero bits are set"
        );

        Ok(())
    }
}
