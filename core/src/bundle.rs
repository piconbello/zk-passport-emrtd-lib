use color_eyre::{
    eyre::{eyre, Context, ContextCompat, Error},
    Result,
};
use der::{Encode, Sequence};
use openssl::nid::Nid;
use openssl::{pkey::PKey, sign::Verifier};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use smallvec::SmallVec;
use x509_cert::certificate::CertificateInner;

use crate::{
    bundle_signature,
    common::nid_serialization,
    dg1::DG1Variant,
    digest,
    document_components::{extract_authority_identifier_key, DocumentComponents},
    master_certs::MasterCert,
    pubkeys::Pubkey,
};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationBundle {
    #[serde_as(as = "Base64")]
    pub dg1: SmallVec<[u8; 128]>,
    pub dg1_variant: DG1Variant,
    #[serde_as(as = "Base64")]
    pub lds: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub signed_attrs: SmallVec<[u8; 128]>,
    // #[serde(with = "object_identifier_serialization")]
    #[serde(with = "nid_serialization")]
    pub digest_algo: Nid,
    pub document_signature: bundle_signature::Signature,
    pub cert_local_pubkey: Pubkey,
    #[serde_as(as = "Base64")]
    pub cert_local_tbs: Vec<u8>,
    // #[serde(with = "object_identifier_serialization")]
    #[serde(with = "nid_serialization")]
    pub cert_local_tbs_digest_algo: Nid,
    pub cert_local_signature: bundle_signature::Signature,
    #[serde_as(as = "Option<Base64>")]
    pub cert_master_subject_key_id: Option<SmallVec<[u8; 20]>>,
    pub cert_master_pubkey: Pubkey,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Signature {
    EC(SignatureEC),
    RSA(SignatureRSA),
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureEC {
    #[serde_as(as = "Base64")]
    pub r: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub s: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureRSA {
    #[serde_as(as = "Base64")]
    pub signature: Vec<u8>,
    pub bitsize: u32,
}

#[derive(Sequence)]
pub struct Asn1Signature {
    r: der::asn1::Int,
    s: der::asn1::Int,
}

impl TryFrom<&[u8]> for SignatureEC {
    type Error = Error;

    fn try_from(signature_der: &[u8]) -> std::result::Result<Self, Self::Error> {
        let signature_asn1: Asn1Signature = der::Decode::from_der(signature_der)?;
        Ok(Self {
            r: signature_asn1.r.as_bytes().into(),
            s: signature_asn1.s.as_bytes().into(),
        })
    }
}

impl TryFrom<&SignatureEC> for Asn1Signature {
    type Error = Error;

    fn try_from(value: &SignatureEC) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            r: der::asn1::Int::new(&value.r)?,
            s: der::asn1::Int::new(&value.s)?,
        })
    }
}

impl TryFrom<&[u8]> for SignatureRSA {
    type Error = Error;

    fn try_from(signature_der: &[u8]) -> std::result::Result<Self, Self::Error> {
        // Parse the DER signature using OpenSSL
        let pkey = PKey::public_key_from_der(signature_der)
            .wrap_err("Failed to parse DER signature for RSA")?;
        let rsa = pkey.rsa()?;

        // Get the size in bits
        let bitsize = rsa.size() * 8;

        Ok(Self {
            signature: signature_der.to_vec(),
            bitsize,
        })
    }
}

fn find_cert_master_pubkey(
    master_certs: &[MasterCert],
    cert: &CertificateInner,
    authority_key_identifier: Option<&SmallVec<[u8; 20]>>,
) -> Result<Pubkey> {
    // Get TBS certificate and signature
    let tbs_cert_der = cert
        .tbs_certificate
        .to_der()
        .wrap_err("Failed to encode TBS certificate")?;
    let cert_signature = cert
        .signature
        .as_bytes()
        .wrap_err("Failed to get certificate signature")?;

    let digest_algo = digest::Sha2::from_signature_algo_pair_oid(&cert.signature_algorithm.oid)
        .wrap_err("cannot determine cert tbs digest algo")?;

    // PASS 1: Try certificates with matching authority key identifier (if provided)
    if let Some(key_id) = &authority_key_identifier {
        let matching_certs: Vec<&MasterCert> = master_certs
            .iter()
            .filter(|mc| mc.subject_key_id.as_ref() == Some(key_id))
            .collect();

        for master_cert in &matching_certs {
            // Try to verify with this master certificate
            if let Ok(pubkey) =
                verify_with_master_cert(master_cert, digest_algo, &tbs_cert_der, cert_signature)
            {
                return Ok(pubkey);
            }
        }
    }

    // PASS 2: If no match found, try all master certificates
    for master_cert in master_certs {
        if let Ok(pubkey) =
            verify_with_master_cert(master_cert, digest_algo, &tbs_cert_der, cert_signature)
        {
            return Ok(pubkey);
        }
    }

    Err(eyre!(
        "No matching master certificate found that can verify the certificate signature"
    ))
}

fn verify_with_master_cert(
    master_cert: &MasterCert,
    digest_algo: digest::Sha2,
    tbs_cert_der: &[u8],
    cert_signature: &[u8],
) -> Result<Pubkey> {
    let pkey: PKey<_> = (&master_cert.pubkey).try_into()?;

    let md = digest_algo.to_message_digest();
    let mut verifier = Verifier::new(md, &pkey)?;
    // panic!("");

    match &master_cert.pubkey {
        Pubkey::EC(_) => {
            // No additional setup needed for ECDSA.  OpenSSL handles padding.
            verifier.update(tbs_cert_der)?;

            if verifier.verify(cert_signature)? {
                Ok(master_cert.pubkey.clone())
            } else {
                Err(eyre!("EC Signature verification failed"))
            }
        }
        Pubkey::RSA(_) => {
            verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
            verifier.update(tbs_cert_der)?;
            if verifier.verify(cert_signature)? {
                Ok(master_cert.pubkey.clone())
            } else {
                Err(eyre!("RSA Signature verification failed"))
            }
        }
    }
}

impl VerificationBundle {
    pub fn bundle(components: &DocumentComponents, master_certs: &[MasterCert]) -> Result<Self> {
        let authority_key_identifier = extract_authority_identifier_key(components.certificate);
        let cert_master = find_cert_master_pubkey(
            master_certs,
            components.certificate,
            authority_key_identifier.as_ref(),
        )
        .wrap_err("Failed to find master public key")?;
        let cert_local_pubkey = Pubkey::try_from(
            &components
                .certificate
                .tbs_certificate
                .subject_public_key_info,
        )?;
        let document_signature =
            bundle_signature::Signature::try_from(components.signer_info).unwrap();

        let cert_local_signature = bundle_signature::Signature::try_from(components.certificate)?;

        let digest_algo = digest::Sha2::from_digest_algo_oid(&components.digest_algo)?.to_nid();
        let cert_local_tbs_digest_algo = digest::Sha2::from_signature_algo_pair_oid(
            &components.certificate.signature_algorithm.oid,
        )?
        .to_nid();

        Ok(Self {
            dg1: SmallVec::from_slice(components.dg1),
            dg1_variant: components.dg1_variant,
            lds: components.lds.into(),
            signed_attrs: components.signed_attrs.to_der()?.into(),
            digest_algo,
            document_signature,
            cert_local_pubkey,
            cert_local_tbs: components.certificate.tbs_certificate.to_der()?,
            cert_local_tbs_digest_algo,
            cert_local_signature,
            cert_master_subject_key_id: authority_key_identifier,
            cert_master_pubkey: cert_master,
        })
    }
}
