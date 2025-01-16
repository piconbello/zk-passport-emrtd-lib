use asn1_rs::{nom::AsBytes, Any, Class, Explicit, FromBer, Oid, TaggedValue};
use base64::{prelude::BASE64_STANDARD, Engine};
use cms::{cert::x509::Certificate, content_info::ContentInfo, signed_data::SignedData};
use color_eyre::{
    eyre::{eyre, Context, ContextCompat},
    Result,
};
use der::{asn1::SetOfVec, Decode, Encode, Sequence};
use digest::{generic_array::GenericArray, Digest, OutputSizeUser};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha2::Sha512;
use smallvec::SmallVec;
use std::{cmp::Ordering, collections::BTreeSet, io::BufRead};

use crate::{document_components::extract_subject_identifier_key, pubkeys_pure::Pubkey};

struct CertIterator<R: BufRead> {
    reader: R,
    current_cert: String,
    is_collecting: bool,
    had_error: bool, // Add this field to track error state
}

impl<R: BufRead> CertIterator<R> {
    fn new(reader: R) -> Self {
        CertIterator {
            reader,
            current_cert: String::new(),
            is_collecting: false,
            had_error: false,
        }
    }
}

impl<R: BufRead> Iterator for CertIterator<R> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Stop iteration if we've encountered an error
        if self.had_error {
            return None;
        }

        const LDIF_CERT_PREFIX: &str = "pkdMasterListContent:: ";
        let mut line = String::new();

        loop {
            line.clear();
            match self.reader.read_line(&mut line) {
                Ok(0) => {
                    // EOF reached
                    if !self.current_cert.is_empty() {
                        // Process any remaining certificate data
                        let cert = std::mem::take(&mut self.current_cert);
                        self.is_collecting = false;
                        let result = BASE64_STANDARD
                            .decode(cert.trim())
                            .wrap_err("eof cert b64 decode");

                        // Set error flag if decode fails
                        if result.is_err() {
                            self.had_error = true;
                        }
                        return Some(result);
                    }
                    return None;
                }
                Ok(_) => {
                    if let Some(stripped) = line.strip_prefix(LDIF_CERT_PREFIX) {
                        if self.is_collecting {
                            // Handle case where we find a new cert before finishing the current one
                            let cert = std::mem::take(&mut self.current_cert);
                            let result = BASE64_STANDARD
                                .decode(cert.trim())
                                .wrap_err("cert b64 decode");

                            if result.is_err() {
                                self.had_error = true;
                                return Some(result);
                            }

                            self.current_cert = stripped.trim().to_string();
                            return Some(result);
                        }

                        self.is_collecting = true;
                        self.current_cert = stripped.trim().to_string();
                        continue;
                    }

                    if !line.starts_with(' ') && self.is_collecting {
                        self.is_collecting = false;
                        let cert = std::mem::take(&mut self.current_cert);
                        let result = BASE64_STANDARD
                            .decode(cert.trim())
                            .wrap_err("cert b64 decode");

                        if result.is_err() {
                            self.had_error = true;
                        }
                        return Some(result);
                    }

                    if self.is_collecting {
                        self.current_cert.push_str(line.trim());
                    }
                }
                Err(e) => {
                    self.had_error = true;
                    return Some(Err(eyre!("read error: {}", e)));
                }
            }
        }
    }
}

fn extract_signed_data_from_cert_ber(cert_ber: &[u8]) -> Result<SignedData> {
    // PKCS#7/CMS ContentInfo structure:
    // SEQUENCE {
    //   contentType OBJECT IDENTIFIER,
    //   content [0] EXPLICIT ANY DEFINED BY contentType
    // }

    // 1. Parse outer SEQUENCE and extract OID
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

    #[derive(Sequence)]
    struct MasterListContent {
        version: u32,
        certificates: SetOfVec<Certificate>,
    }

    let master_list = MasterListContent::from_der(econtent.value())
        .wrap_err("Failed to decode master list content")?;

    Ok(master_list.certificates.into_vec())
}

pub fn deduplicate_certificates(certs: Vec<Certificate>) -> Vec<Certificate> {
    #[derive(Eq, PartialEq)]
    struct CertificateWithHash {
        hash: GenericArray<u8, <Sha512 as OutputSizeUser>::OutputSize>,
        cert: Certificate,
    }

    impl From<Certificate> for CertificateWithHash {
        fn from(cert: Certificate) -> Self {
            let hash = Sha512::digest(
                cert.tbs_certificate
                    .to_der()
                    .expect("we deserialized it should not fail"),
            );

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
    certs
        .into_iter()
        .map(CertificateWithHash::from)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|wrapped| wrapped.cert)
        .collect()
}

pub fn extract_master_certificates<R: BufRead>(reader: R) -> Result<Vec<Certificate>> {
    let certs = CertIterator::new(reader)
        .map(|root| root.and_then(|der| extract_certificates_from_cert_der(&der)))
        .flatten_ok()
        .collect::<Result<Vec<_>>>()?;

    Ok(deduplicate_certificates(certs))
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MasterCert {
    pub pubkey: Pubkey,
    #[serde_as(as = "Base64")]
    pub subject_key_id: SmallVec<[u8; 20]>,
}

pub fn distill_master_certificates(certs: &[Certificate]) -> Result<Vec<MasterCert>> {
    let mut mastercerts: Vec<_> = certs
        .iter()
        .map(|cert| {
            let pubkey = Pubkey::try_from(&cert.tbs_certificate.subject_public_key_info)?;
            let subject_key_id = extract_subject_identifier_key(cert)?;
            Ok(MasterCert {
                pubkey,
                subject_key_id,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    mastercerts.sort_unstable_by(|a, b| a.subject_key_id.cmp(&b.subject_key_id));
    Ok(mastercerts)
}
