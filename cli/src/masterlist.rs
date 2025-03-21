use color_eyre::eyre::{eyre, Context, Result};
use emrtd_core::master_certs;
use emrtd_core::openssl::pkey::PKey;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::PathBuf;

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct MasterlistSource {
    #[serde_as(as = "Option<Base64>")]
    sha2_256: Option<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Masterlist {
    pub pairs: Vec<master_certs::MasterCert>,
    pub source: Option<MasterlistSource>,
}

pub fn parse_masterlist_from_ldif(ldif_file: &PathBuf) -> Result<Masterlist> {
    let master_pairs = {
        let f = File::open(ldif_file).wrap_err("opening ldif file")?;
        let reader = BufReader::new(f);
        let master_certs = master_certs::extract_master_certificates(reader)?;
        master_certs::distill_master_certificates(&master_certs)
    }?;
    let digest: [u8; 32] = {
        let mut f = File::open(ldif_file).wrap_err("opening ldif file")?;
        let mut hasher = Sha256::new();
        io::copy(&mut f, &mut hasher).wrap_err("hashing ldif file")?;
        hasher.finalize().into()
    };
    Ok(Masterlist {
        pairs: master_pairs,
        source: Some(MasterlistSource {
            sha2_256: Some(digest),
        }),
    })
}

pub struct PemIterator<'a> {
    content: &'a str,
    position: usize,
}

impl<'a> PemIterator<'a> {
    pub fn new(content: &'a str) -> Self {
        PemIterator {
            content,
            position: 0,
        }
    }
}

impl<'a> Iterator for PemIterator<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        // If we've reached the end of the content, return None
        if self.position >= self.content.len() {
            return None;
        }

        // Find the next BEGIN marker
        let begin_marker = "-----BEGIN ";
        let remaining = &self.content[self.position..];
        let begin_pos = remaining.find(begin_marker)?;
        let start_pos = self.position + begin_pos;

        // Find the corresponding END marker
        let end_marker = "-----END ";
        let after_begin = &self.content[start_pos..];
        let end_marker_pos = after_begin.find(end_marker)?;
        let end_marker_start = start_pos + end_marker_pos;

        // Find the end of the END line
        let remaining = &self.content[end_marker_start..];
        let end_line_end = remaining.find('\n').unwrap_or(remaining.len());
        let end_pos = end_marker_start + end_line_end;

        // Extract the complete PEM block
        let pem_block = &self.content[start_pos..end_pos];

        // Update position to continue from after this PEM block
        self.position = end_pos + 1;

        Some(pem_block)
    }
}

// Helper function that returns the iterator
pub fn parse_multi_pem(multi: &str) -> PemIterator {
    PemIterator::new(multi)
}

pub fn parse_masterlist_from_pem(pem_file: &PathBuf) -> Result<Masterlist> {
    let pem_content = fs::read_to_string(pem_file).wrap_err("reading PEM file")?;
    let pem_blocks = parse_multi_pem(&pem_content);

    let mut pairs = Vec::new();
    for pem in pem_blocks {
        let key = PKey::private_key_from_pem(pem.as_bytes())?;
        let pubkey = key.public_key_to_der()?.as_slice().try_into()?;
        pairs.push(master_certs::MasterCert {
            pubkey,
            subject_key_id: None,
        });
    }

    // Generate digest of the file
    let digest: [u8; 32] = {
        let mut f = File::open(pem_file).wrap_err("opening PEM file")?;
        let mut hasher = Sha256::new();
        io::copy(&mut f, &mut hasher).wrap_err("hashing PEM file")?;
        hasher.finalize().into()
    };

    Ok(Masterlist {
        pairs,
        source: Some(MasterlistSource {
            sha2_256: Some(digest),
        }),
    })
}

pub fn handle_generate_masterlist(input_file: &PathBuf) -> Result<()> {
    let extension = input_file
        .extension()
        .ok_or_else(|| eyre!("File has no extension"))?
        .to_string_lossy()
        .to_lowercase();

    let masterlist = match extension.as_ref() {
        "ldif" => parse_masterlist_from_ldif(input_file),
        "pem" => parse_masterlist_from_pem(input_file),
        _ => Err(eyre!(
            "Unsupported file extension: {}. Must be .ldif or .pem",
            extension
        )),
    }?;

    // Output to stdout
    let stdout = std::io::stdout();
    let stdout_handle = stdout.lock();
    serde_json::to_writer_pretty(stdout_handle, &masterlist)
        .wrap_err("writing masterlist to stdout")?;

    Ok(())
}

pub fn parse_masterlist_from_json(masterlist_json_file: &PathBuf) -> Result<Masterlist> {
    let extension = masterlist_json_file
        .extension()
        .ok_or_else(|| eyre!("File has no extension"))?
        .to_string_lossy()
        .to_lowercase();

    if extension != "json" {
        return Err(eyre!(
            "Expected .json file extension, but got: {}",
            extension
        ));
    }

    let file = File::open(masterlist_json_file).wrap_err("opening JSON masterlist file")?;
    let reader = BufReader::new(file);
    let masterlist: Masterlist =
        serde_json::from_reader(reader).wrap_err("deserializing JSON masterlist")?;

    Ok(masterlist)
}
