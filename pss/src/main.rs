//! PSS padding reference implementation.
//! This example demonstrates how to use the PSS implementation to encode and verify messages.

use color_eyre::Result;
use digest::DynDigest;
use pss::pss::{div_ceil, emsa_pss_encode, emsa_pss_verify};
use sha2::Sha256;

fn main() -> Result<()> {
    color_eyre::install()?;

    // PSS Configuration parameters
    let key_bits: usize = 2048;
    const HASH_LEN: usize = 32; // SHA-256
    const SALT_LEN: usize = HASH_LEN;
    let em_bits: usize = key_bits - 1;

    println!("=== PSS Padding Example ===");
    println!("- Key size: {} bits", key_bits);
    println!("- Hash: SHA-256 ({} bytes)", HASH_LEN);
    println!("- Salt length: {} bytes", SALT_LEN);
    println!(
        "- EM bits: {} (em_len: {} bytes)",
        em_bits,
        div_ceil(em_bits, 8)
    );
    println!();

    // Example message
    let message = b"";
    println!("Message: \"{}\"", String::from_utf8_lossy(message));

    // 1. Calculate message hash
    let mut hasher = <Sha256 as sha2::Digest>::new();
    DynDigest::update(&mut hasher, message);
    let message_hash = DynDigest::finalize_reset(&mut hasher);
    println!("Message hash: {}", hex::encode(&message_hash));

    // 2. Create salt (normally random, fixed here for demonstration)
    let salt = [42u8; SALT_LEN];
    println!("Salt: {}", hex::encode(&salt));

    // 3. Encode message with PSS
    let mut encode_hasher = <Sha256 as sha2::Digest>::new();
    let encoded_message = emsa_pss_encode(&message_hash, em_bits, &salt, &mut encode_hasher)?;

    println!("Encoded message (hex): {}", hex::encode(&encoded_message));

    // println!("Encoded message ({} bytes):", encoded_message.len());
    // for i in 0..encoded_message.len() {
    //     if i % 16 == 0 {
    //         print!("\n{:04x}:  ", i);
    //     }
    //     print!("{:02x} ", encoded_message[i]);
    // }
    // println!("\n");

    // 4. Verify the encoded message
    let mut em_to_verify = encoded_message.clone();
    let mut verify_hasher = <Sha256 as sha2::Digest>::new();
    match emsa_pss_verify(
        &message_hash,
        &mut em_to_verify,
        SALT_LEN,
        &mut verify_hasher,
        key_bits,
    ) {
        Ok(_) => println!("✅ Verification successful!"),
        Err(e) => println!("❌ Verification failed: {}", e),
    }

    println!("\n--- Example Complete ---");
    Ok(())
}
