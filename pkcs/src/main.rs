mod copied;
use crate::copied::{pkcs1v15_generate_prefix, pkcs1v15_sign_unpad};
use sha2::{Digest, Sha256}; // Or Sha512 if needed
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Configuration ---
    // Typically 4096 or 2048 for your use case
    const KEY_SIZE_BITS: usize = 4096;
    const KEY_SIZE_BYTES: usize = KEY_SIZE_BITS / 8;
    type HASH_ALGO = Sha256; // Change to Sha512 if necessary

    // --- Get Inputs from Command Line Arguments ---
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: cargo run <hash_hex> <padded_message_hex>");
        eprintln!("\nExample:");
        eprintln!("  <hash_hex>: The raw SHA-256 hash of the TBS data (e.g., from TS logs)");
        eprintln!("  <padded_message_hex>: The hex representation of the expected padded message");
        eprintln!(
            "                        (e.g., from expectedMessage_pb.toBigint().toString(16) in TS logs,"
        );
        eprintln!(
            "                         MUST be zero-padded to {} hex characters)",
            KEY_SIZE_BYTES * 2
        );
        std::process::exit(1);
    }

    let hash_hex = &args[1];
    let padded_message_hex = &args[2];

    // --- Data Preparation ---
    let hashed_bytes = hex::decode(hash_hex)?;
    let padded_message_bytes = hex::decode(padded_message_hex)?;

    // --- Input Validation ---
    let expected_hash_len = <HASH_ALGO as Digest>::output_size();
    if hashed_bytes.len() != expected_hash_len {
        eprintln!(
            "Error: Provided hash length ({}) does not match expected {} length ({} bytes).",
            hashed_bytes.len(),
            std::any::type_name::<HASH_ALGO>(),
            expected_hash_len
        );
        std::process::exit(1);
    }

    if padded_message_bytes.len() != KEY_SIZE_BYTES {
        eprintln!(
            "Error: Padded message length ({}) does not match key size ({} bytes). Ensure hex string is zero-padded.",
            padded_message_bytes.len(),
            KEY_SIZE_BYTES
        );
        std::process::exit(1);
    }

    // --- Generate DigestInfo Prefix ---
    // This generates the ASN.1 DER structure for the hash algorithm identifier
    let prefix = pkcs1v15_generate_prefix::<HASH_ALGO>();

    // --- Verification using Rust Reference Implementation ---
    println!("--- Verifying PKCS#1 v1.5 Padding Structure ---");
    println!(
        "Key Size:       {} bits ({} bytes)",
        KEY_SIZE_BITS, KEY_SIZE_BYTES
    );
    println!("Hash Algorithm: {}", std::any::type_name::<HASH_ALGO>());
    println!("Expected Hash:  {}", hash_hex);
    println!("Padded Msg len: {}", padded_message_bytes.len());
    // println!("Padded Msg Hex: {}", padded_message_hex); // Can be very long

    match pkcs1v15_sign_unpad(
        &prefix,               // Expected DigestInfo prefix
        &hashed_bytes,         // Expected raw hash
        &padded_message_bytes, // The candidate message to check
        KEY_SIZE_BYTES,        // Expected total length
    ) {
        Ok(()) => {
            println!("\n✅ SUCCESS: Padding structure is VALID according to the Rust reference.");
        }
        Err(e) => {
            eprintln!("\n❌ FAILURE: Padding structure is INVALID.");
            eprintln!("Error from pkcs1v15_sign_unpad: {:?}", e);

            // --- Detailed Debugging ---
            println!("\n--- Debug Info ---");
            println!(
                "Expected Prefix (DigestInfo): {:x?} ({} bytes)",
                prefix,
                prefix.len()
            );
            println!(
                "Expected Hash:                {:x?} ({} bytes)",
                hashed_bytes,
                hashed_bytes.len()
            );

            let expected_total_t_len = prefix.len() + hashed_bytes.len();
            if KEY_SIZE_BYTES < expected_total_t_len + 11 {
                println!("Key size too small for padding + hash + prefix!");
            } else {
                // Check 0x00, 0x01 start
                println!("Actual Bytes [0..2]: {:x?}", &padded_message_bytes[..2]);
                if padded_message_bytes[0] != 0x00 || padded_message_bytes[1] != 0x01 {
                    println!(" -> FAIL: Should start with 0x0001");
                }

                // Check 0x00 separator
                let separator_index = KEY_SIZE_BYTES - expected_total_t_len - 1;
                println!(
                    "Actual Byte at separator index [{}]: {:02x}",
                    separator_index, padded_message_bytes[separator_index]
                );
                if padded_message_bytes[separator_index] != 0x00 {
                    println!(" -> FAIL: Separator byte before T should be 0x00");
                }

                // Check FF padding
                let ff_padding = &padded_message_bytes[2..separator_index];
                let all_ff = ff_padding.iter().all(|&b| b == 0xff);
                println!("Padding block length: {}", ff_padding.len());
                if ff_padding.len() < 8 {
                    println!(" -> FAIL: Padding block must be at least 8 bytes");
                }
                if !all_ff {
                    println!(" -> FAIL: Not all padding bytes are 0xFF");
                    if let Some(non_ff_pos) = ff_padding.iter().position(|&b| b != 0xff) {
                        println!(
                            "    -> First non-FF byte found at padding index {}",
                            non_ff_pos
                        );
                    }
                }

                // Check Prefix (T part 1)
                let actual_prefix =
                    &padded_message_bytes[separator_index + 1..separator_index + 1 + prefix.len()];
                println!("Actual Prefix in Message:     {:x?}", actual_prefix);
                if prefix != actual_prefix {
                    println!(" -> FAIL: Prefix mismatch");
                }

                // Check Hash (T part 2)
                let actual_hash = &padded_message_bytes[KEY_SIZE_BYTES - hashed_bytes.len()..];
                println!("Actual Hash in Message:       {:x?}", actual_hash);
                if hashed_bytes != actual_hash {
                    println!(" -> FAIL: Hash mismatch");
                }
            }
            println!("------------------");
        }
    }

    Ok(())
}
