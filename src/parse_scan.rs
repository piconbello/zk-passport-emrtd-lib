use cms::cert::x509::certificate::CertificateInner;
use cms::signed_data::{EncapsulatedContentInfo, SignedAttributes, SignerInfo};
use cms::{content_info::ContentInfo, signed_data::SignedData};
use color_eyre::eyre::{bail, Context, ContextCompat, Error, Result};
use const_oid::db::rfc5912::{ID_SHA_512, SECP_521_R_1};
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{AnyRef, Decode, Encode, SliceReader};
use digest::Digest;
use ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use elliptic_curve::sec1::EncodedPoint;
use p521::NistP521;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use sha2::Sha512; // Add these imports

use crate::dg1::Dg1Td3;

const OID_MRTD_SIGNATURE_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.136.1.1.1");

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportScan {
    #[serde_as(as = "Base64")]
    pub sod: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub dg1: Dg1Td3,
}

pub fn parse_sod(sod_bytes: &[u8]) -> Result<SignedData> {
    let mut reader = SliceReader::new(sod_bytes).expect("infallible");

    // handle ICAO application tag wrapper
    let app23 = AnyRef::decode(&mut reader).wrap_err("sod must start with APPLICATION [23] tag")?;

    let content_info =
        ContentInfo::from_der(app23.value()).wrap_err("content info parsing of sod")?;

    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .wrap_err("signed data parsing of sod")?;

    Ok(signed_data)
}

pub fn extract_lds_from_econtent(enc_content: &EncapsulatedContentInfo) -> Result<Vec<u8>> {
    if enc_content.econtent_type != OID_MRTD_SIGNATURE_DATA {
        bail!("encapsulated content is not mrtd signature data");
    }

    let any = match &enc_content.econtent {
        None => bail!("encapsulated content does not contain data"),
        Some(any) => any,
    };

    let oc = any.decode_as::<OctetString>()?;

    let lds_serialized = oc.into_bytes();
    Ok(lds_serialized)
}

pub fn extract_signer_info(sod: &SignedData) -> Result<&SignerInfo> {
    sod.signer_infos
        .0
        .as_ref()
        .first()
        .wrap_err("there must be one signer info")
}

pub fn extract_signed_attrs(signer_info: &SignerInfo) -> Result<Vec<u8>> {
    let signed_attrs: &SignedAttributes = signer_info
        .signed_attrs
        .as_ref()
        .wrap_err("signed attrs not present")?;

    Ok(signed_attrs.to_der().expect("infallible"))
}

pub fn extract_certificate(sod: &SignedData) -> Result<&CertificateInner> {
    let certiticate_set = sod
        .certificates
        .as_ref()
        .wrap_err("sod must have 'certificates'")?;
    let cert_enum = certiticate_set
        .0
        .as_ref()
        .first()
        .wrap_err("there must be one cert")?;
    let cert = match cert_enum {
        cms::cert::CertificateChoices::Certificate(cert) => cert,
        other => bail!("Expected Certificate variant, got {:?}", other),
    };
    Ok(cert)
}

pub struct PassportVerificationInput<'a> {
    pub signed_attrs: Vec<u8>,
    pub algo_digest: ObjectIdentifier,
    pub algo_signature: ObjectIdentifier,
    pub verifying_key: &'a [u8],
    pub signature: &'a [u8],
}
impl<'a> PassportVerificationInput<'a> {
    pub fn verify(&self) -> Result<()> {
        if self.algo_digest != ID_SHA_512 {
            bail!("Unexpected digest algorithm");
        }
        if self.algo_signature != SECP_521_R_1 {
            bail!("Unexpected signature algorithm");
        }

        // public key parsing
        let encoded_point = EncodedPoint::<NistP521>::from_bytes(self.verifying_key)?;

        // Create VerifyingKey instead of PublicKey
        let verifying_key: VerifyingKey<NistP521> =
            VerifyingKey::from_encoded_point(&encoded_point).expect("Invalid public key encoding");

        let signature = Signature::<NistP521>::from_der(self.signature)?;

        let payload = Sha512::digest(&self.signed_attrs);

        verifying_key
            .verify_prehash(&payload, &signature)
            .wrap_err("passport verification failed")
    }
}

pub fn extract_passport_verification_input<'a>(
    signer_info: &'a SignerInfo,
    cert: &'a CertificateInner,
) -> Result<PassportVerificationInput<'a>> {
    let algo_digest = signer_info.digest_alg.oid;

    let algo_signature = cert
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .parameters
        .as_ref()
        .unwrap()
        .decode_as::<ObjectIdentifier>()?;

    let verifying_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    let signature = signer_info.signature.as_bytes();

    let signed_attrs: &SignedAttributes = signer_info
        .signed_attrs
        .as_ref()
        .wrap_err("signed attrs not present")?;

    Ok(PassportVerificationInput {
        signed_attrs: signed_attrs.to_der()?,
        algo_digest,
        algo_signature,
        verifying_key,
        signature,
    })
}

#[serde_as]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportProvable {
    #[serde_as(as = "Base64")]
    pub dg1: Dg1Td3,
    #[serde_as(as = "Base64")]
    pub lds: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub signed_attrs: Vec<u8>,
}

impl TryFrom<&PassportScan> for PassportProvable {
    type Error = Error;

    fn try_from(scan: &PassportScan) -> std::result::Result<Self, Self::Error> {
        let sod = parse_sod(&scan.sod)?;
        let lds = extract_lds_from_econtent(&sod.encap_content_info)?;
        let signer_info = extract_signer_info(&sod)?;
        let signed_attrs = extract_signed_attrs(signer_info)?;
        Ok(PassportProvable {
            dg1: scan.dg1,
            lds,
            signed_attrs,
        })
    }
}
