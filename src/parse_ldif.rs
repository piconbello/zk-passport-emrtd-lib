use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use clap::builder::OsStr;
use cms::cert::x509::ext::pkix::SubjectKeyIdentifier;
use cms::cert::x509::Certificate;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use color_eyre::eyre::{bail, eyre, Context, ContextCompat};
use color_eyre::Result;
use const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER;
use const_oid::db::rfc5912::{
    ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_224_R_1, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1,
};
use const_oid::db::DB;
use der::asn1::{BitString, SetOfVec};
use der::{Any, Decode, Encode, Sequence};
use digest::Digest;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::RsaPublicKey;
use sha2::Sha512;
use smallvec::SmallVec;
use spki::{DecodePublicKey, ObjectIdentifier, SubjectPublicKeyInfo};
use std::cmp::Ordering;
use std::collections::BTreeSet;
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
        if let Some(stripped) = line.strip_prefix(LDIF_CERT_PREFIX) {
            is_collecting = true;
            current_cert = stripped.to_string();
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
    signed_data_der.extend_from_slice(inner_data); // Add content
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

    let mut all_certs = Vec::new();
    for cert_der in &cert_ders {
        let certs = extract_certificates_from_cert_der(cert_der)?;
        all_certs.extend(certs);
    }

    let deduplicated_certs = deduplicate_certificates(all_certs);

    Ok(deduplicated_certs)
}

pub fn extract_subject_identifier_key(master_cert: &Certificate) -> Result<SmallVec<[u8; 20]>> {
    let exts = master_cert
        .tbs_certificate
        .extensions
        .as_ref()
        .wrap_err("need extensions in cert")?;

    let ext = exts
        .iter()
        .find(|ext| ext.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)
        .wrap_err("need subject key extension")?;

    let ki: SmallVec<[u8; 20]> = match SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
        Ok(ski) => {
            let ki = ski.0.as_bytes();
            ki.into()
        }
        Err(_) => {
            let ki = ext.extn_value.as_bytes();
            ki.into()
        }
    };

    Ok(ki)
}

#[allow(dead_code)]
fn debug_ec_key_failure(info: &SubjectPublicKeyInfo<Any, BitString>, key_bytes: &[u8]) -> String {
    let mut debug_info = String::new();

    let curve_guess = match key_bytes.len() {
        65 => "P-256",
        97 => "P-384",
        129 => "P-521",
        _ => "unknown",
    };

    debug_info.push_str(&format!(
        "\nEC Key Debug:\n\
         Raw length: {} (suggests {})\n\
         First 20 bytes: {}\n",
        key_bytes.len(),
        curve_guess,
        BASE64_STANDARD.encode(&key_bytes[..20])
    ));

    if let Some(params) = info.algorithm.parameters.as_ref() {
        debug_info.push_str("Parameters analysis:\n");
        // Try to extract curve OID or named curve
        if let Ok(param_der) = params.to_der() {
            debug_info.push_str(&format!(
                "Parameter DER: {}\n",
                BASE64_STANDARD.encode(&param_der)
            ));
        }
    }

    debug_info
}

pub fn extract_signing_algo(master_cert: &Certificate) -> Result<ObjectIdentifier> {
    let info = &master_cert.tbs_certificate.subject_public_key_info;

    if info.algorithm.oid == ID_EC_PUBLIC_KEY {
        let key_bytes = info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| eyre!("Invalid EC key: BIT STRING not octet-aligned"))?;

        if p224::PublicKey::from_sec1_bytes(key_bytes).is_ok() {
            return Ok(SECP_224_R_1);
        }

        if p256::PublicKey::from_sec1_bytes(key_bytes).is_ok() {
            return Ok(SECP_256_R_1);
        }

        if p384::PublicKey::from_sec1_bytes(key_bytes).is_ok() {
            return Ok(SECP_384_R_1);
        }

        if p521::PublicKey::from_sec1_bytes(key_bytes).is_ok() {
            return Ok(SECP_521_R_1);
        }

        eprintln!(
            "EC FAIL CERT PEM {}",
            BASE64_STANDARD.encode(master_cert.to_der().unwrap())
        );
        bail!("EC failed {}", key_bytes.len());
        // bail!("EC failed {}", debug_ec_key_failure(info, key_bytes));
    } else if info.algorithm.oid == RSA_ENCRYPTION {
        let info_der = &info.to_der().expect("serializes");

        if RsaPublicKey::from_public_key_der(info_der).is_ok() {
            return Ok(RSA_ENCRYPTION);
        } else if RsaPublicKey::from_pkcs1_der(info.subject_public_key.raw_bytes()).is_ok() {
            return Ok(RSA_ENCRYPTION);
        }

        // Then try parsing just the raw key components
        let raw_key = info.subject_public_key.raw_bytes();
        if RsaPublicKey::from_pkcs1_der(raw_key).is_ok() {
            return Ok(RSA_ENCRYPTION);
        }

        // If both attempts fail, manually parse the RSA sequence components
        use asn1_rs::{nom::AsBytes, FromBer, Integer};
        use rsa::BigUint;
        // println!(
        //     "raw_key first few bytes: {:02x?}",
        //     &raw_key[..std::cmp::min(20, raw_key.len())]
        // );
        // println!("{}", BASE64_STANDARD.encode(info_der));
        if let Ok((_remainder, sequence)) = asn1_rs::Sequence::from_ber(raw_key) {
            // println!("Sequence parsed successfully");
            let seq_data = sequence.content.as_bytes();
            if let Ok((e_data, n)) = Integer::from_ber(seq_data) {
                // println!("First integer (n) parsed successfully");
                if let Ok((remainder, e)) = Integer::from_ber(e_data) {
                    // println!("Second integer (e) parsed successfully");
                    // println!("Remainder empty: {}", remainder.is_empty());
                    if remainder.is_empty() {
                        let n = BigUint::from_bytes_be(n.as_ref());
                        let e = BigUint::from_bytes_be(e.as_ref());
                        // println!("bits: {}, n: {}", n.bits(), n);
                        // println!("e: {}", e);
                        if RsaPublicKey::new_with_max_size(n, e, 16384).is_ok() {
                            return Ok(RSA_ENCRYPTION);
                        }
                    }
                }
            }
        }
        bail!(
            "RSA public key parsing failed for key: {}",
            BASE64_STANDARD.encode(info.to_der().map_err(|e| eyre!("der error: {}", e))?)
        );
    }
    bail!(
        "{} = {:?}",
        info.algorithm.oid,
        DB.by_oid(&info.algorithm.oid)
    );
}
