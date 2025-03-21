use color_eyre::eyre::{eyre, Context, ContextCompat, Result};
use emrtd_core::bundle_mock_master;
use emrtd_core::bundle_verify::Verify;
use emrtd_core::openssl::nid::Nid;
use emrtd_core::openssl::{ec::EcKey, rsa::Rsa};
use serde::Deserialize;
use serde_with::{serde_as, Bytes};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::masterlist::PemIterator;

pub fn shortname_to_nid(short_name: &str) -> Result<Nid> {
    // Convert to CString for FFI
    let c_str = std::ffi::CString::new(short_name)
        .map_err(|e| eyre!("Invalid string for NID conversion: {}", e))?;

    // Use unsafe block to call OpenSSL's OBJ_sn2nid
    let nid = unsafe { emrtd_core::openssl_sys::OBJ_sn2nid(c_str.as_ptr()) };

    if nid == 0 {
        return Err(eyre!("Unknown OpenSSL object name: {}", short_name));
    }

    Ok(Nid::from_raw(nid))
}

#[serde_as]
#[derive(Deserialize, Debug)]
struct MockConfig {
    #[serde_as(as = "Option<Bytes>")]
    mrz: Option<[u8; 88]>,
    dgs: Option<BTreeSet<u8>>,
    digest_algo_head: Option<String>,
    digest_algo_tail: Option<String>,
    master_pems_file: PathBuf,
    master_key_index: usize,
}

pub fn handle_mock(mock_config_path: &Path) -> Result<()> {
    let config_text = fs::read_to_string(mock_config_path)?;
    let config: MockConfig = toml::from_str(&config_text)?;

    let master_key = {
        let master_pems =
            fs::read_to_string(config.master_pems_file).wrap_err("reading PEM file")?;
        let master_pem = PemIterator::new(&master_pems)
            .nth(config.master_key_index)
            .wrap_err("nth PEM do not exist")?;

        // Try parsing as RSA first, then EC if that fails
        if let Ok(rsa) = Rsa::private_key_from_pem(master_pem.as_bytes()) {
            bundle_mock_master::MasterPrivateKey::RSA(rsa)
        } else if let Ok(ec) = EcKey::private_key_from_pem(master_pem.as_bytes()) {
            bundle_mock_master::MasterPrivateKey::EC(ec)
        } else {
            return Err(eyre!("Failed to parse PEM as either RSA or EC private key"));
        }
    };

    // Convert our config to the core library's MockConfig
    let core_config = emrtd_core::bundle_mock_master::MockConfig {
        mrz: config
            .mrz
            .unwrap_or(*emrtd_core::bundle_mock_master::MRZ_FRODO),
        dgs: config
            .dgs
            .unwrap_or_else(|| BTreeSet::from([1, 2, 3, 11, 12, 14])),
        digest_algo_head: shortname_to_nid(
            &config
                .digest_algo_head
                .unwrap_or_else(|| "SHA256".to_string()),
        )
        .wrap_err("digest algo head nid")?,
        digest_algo_tail: shortname_to_nid(
            &config
                .digest_algo_tail
                .unwrap_or_else(|| "SHA256".to_string()),
        )
        .wrap_err("digest algo tail nid")?,
        master_key,
    };

    // Create the mock bundle
    let bundle = core_config.mock().wrap_err("mocking")?;

    // Verify the bundle
    bundle.verify().wrap_err("verifying")?;

    // Output the bundle as JSON
    println!("{}", serde_json::to_string_pretty(&bundle)?);
    Ok(())
}
