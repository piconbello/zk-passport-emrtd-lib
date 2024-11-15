use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use clap::builder::OsStr;
use cms::cert::x509::Certificate;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use color_eyre::eyre::{bail, Context, ContextCompat};
use color_eyre::Result;
use der::asn1::SetOfVec;
use der::{Decode, Encode, Sequence};
use digest::Digest;
use sha2::{Sha256, Sha512};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

const LDIF_CERT_PREFIX: &str = "pkdMasterListContent:: ";
const FILE_EXTENSION: &str = "ldif";

/// Extracts CMS structures from LDIF content
fn extract_master_certs_der_from_ldif(content_ldif: &str) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();
    let mut current_cert = String::new();
    let mut is_collecting = false;

    for line in content_ldif.lines() {
        if line.starts_with(LDIF_CERT_PREFIX) {
            is_collecting = true;
            current_cert = line[LDIF_CERT_PREFIX.len()..].to_string();
            continue;
        }

        if !line.starts_with(' ') && is_collecting {
            if let Ok(decoded) = BASE64_STANDARD.decode(current_cert.trim()) {
                certs.push(decoded);
            }
            current_cert.clear();
            is_collecting = false;
            continue;
        }

        if is_collecting {
            current_cert.push_str(line.trim());
        }
    }

    if !current_cert.is_empty() {
        if let Ok(decoded) = BASE64_STANDARD.decode(current_cert.trim()) {
            certs.push(decoded);
        }
    }

    certs
}

#[derive(Sequence)]
struct MasterListContent {
    version: u32,
    certificates: SetOfVec<Certificate>,
}

fn extract_signed_data_from_cert_ber(cert_ber: &[u8]) -> Result<SignedData> {
    // PKCS#7/CMS ContentInfo structure:
    // SEQUENCE {
    //   contentType OBJECT IDENTIFIER,
    //   content [0] EXPLICIT ANY DEFINED BY contentType
    // }

    // 1. Parse outer SEQUENCE and extract OID
    use asn1_rs::{nom::AsBytes, Any, Class, Explicit, FromBer, Oid, TaggedValue};
    let (_, seq) = asn1_rs::Sequence::from_ber(cert_ber).wrap_err("outer sequence")?;
    let (rest, _content_type) = Oid::from_ber(seq.content.as_bytes()).wrap_err("content type")?;

    // 2. Parse [0] EXPLICIT tagged content
    let (_, content) =
        TaggedValue::<Any, asn1_rs::Error, Explicit, { Class::CONTEXT_SPECIFIC }, 0>::from_ber(
            rest,
        )
        .wrap_err("tagged content")?;

    // 3. Get the SignedData content (which is BER-encoded)
    let inner_data = content.into_inner().data;

    // 4. Convert BER to DER by wrapping in proper DER SEQUENCE
    // Some implementations use BER indefinite length encoding (indicated by 0x80),
    // but we need DER for the cms library which expects strict DER encoding
    let mut signed_data_der = Vec::new();
    signed_data_der.extend_from_slice(&[0x30, 0x82]); // SEQUENCE tag and length
    let content_len = inner_data.len();
    signed_data_der.extend_from_slice(&[(content_len >> 8) as u8, content_len as u8]); // Add length bytes
    signed_data_der.extend_from_slice(&inner_data); // Add content
    let signed_data = SignedData::from_der(&signed_data_der).wrap_err("signed data")?;
    Ok(signed_data)
}

/// Extract certificates from CMS structure
fn extract_certificates_from_cert_der(cert_der: &[u8]) -> Result<Vec<Certificate>> {
    let signed_data: Result<SignedData> = match ContentInfo::from_der(cert_der) {
        Ok(content_info) => {
            let content = content_info.content.to_der().wrap_err("content")?;
            let signed_data = SignedData::from_der(&content).wrap_err("signed data")?;
            Ok(signed_data)
        }
        Err(_) => {
            // If DER parsing fails, handle as BER-encoded data
            extract_signed_data_from_cert_ber(cert_der)
        }
    };

    let signed_data = signed_data.wrap_err("parsing signed attrs from master cert failed")?;

    let econtent = signed_data
        .encap_content_info
        .econtent
        .wrap_err("no econtent in master cert")?;

    let master_list = MasterListContent::from_der(econtent.value())
        .wrap_err("Failed to decode master list content")?;

    Ok(master_list.certificates.into_vec())
}

#[derive(Eq, PartialEq)]
struct CertificateWithHash {
    hash: Vec<u8>,
    cert: Certificate,
}

impl From<Certificate> for CertificateWithHash {
    fn from(cert: Certificate) -> Self {
        let hash = Sha512::digest(
            cert.tbs_certificate
                .to_der()
                .expect("we deserialized it should not fail"),
        )
        .to_vec();

        CertificateWithHash { hash, cert }
    }
}

impl Ord for CertificateWithHash {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hash.cmp(&other.hash)
    }
}

impl PartialOrd for CertificateWithHash {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn deduplicate_certificates(certs: Vec<Certificate>) -> Vec<Certificate> {
    certs
        .into_iter()
        .map(CertificateWithHash::from)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|wrapped| wrapped.cert)
        .collect()
}

/// Main function to process LDIF file and extract certificates
pub fn certificates_from_ldif(ldif_path: &PathBuf) -> Result<Vec<Certificate>> {
    if ldif_path.extension() != Some(&OsStr::from(FILE_EXTENSION)) {
        bail!("Invalid file type. Expected {} file", FILE_EXTENSION);
    }

    let content = fs::read_to_string(ldif_path).wrap_err("Failed to read LDIF file")?;

    let cert_ders = extract_master_certs_der_from_ldif(&content);

    println!("Number of CMS structures: {}", cert_ders.len());

    let mut all_certs = Vec::new();
    for cert_der in &cert_ders {
        let certs = extract_certificates_from_cert_der(cert_der)?;
        println!("CMS had {} certificates", certs.len());
        all_certs.extend(certs);
    }

    println!(
        "Total certificates before deduplication: {}",
        all_certs.len()
    );

    let deduplicated_certs = deduplicate_certificates(all_certs);
    println!(
        "Total unique certificates after deduplication: {}",
        deduplicated_certs.len()
    );

    Ok(deduplicated_certs)
}
