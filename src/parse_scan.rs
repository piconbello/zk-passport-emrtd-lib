use cms::cert::x509::certificate::CertificateInner;
use cms::signed_data::{EncapsulatedContentInfo, SignedAttributes, SignerInfo};
use cms::{content_info::ContentInfo, signed_data::SignedData};
use color_eyre::eyre::{bail, eyre, Context, ContextCompat, Error, Result};
use const_oid::db::rfc5912::{
    ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512, SECP_224_R_1, SECP_256_R_1, SECP_384_R_1,
    SECP_521_R_1,
};
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{AnyRef, Decode, Encode, SliceReader};
use digest::Digest;
use ecdsa::signature::hazmat::PrehashVerifier;
use ecdsa::{Signature, VerifyingKey};
use k256::Secp256k1;
use p224::NistP224;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use crate::dg1::Dg1Td3;

const OID_MRTD_SIGNATURE_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.136.1.1.1");
const SECP_256_K_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

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
        let digest = match self.algo_digest {
            ID_SHA_256 => Sha256::digest(&self.signed_attrs).to_vec(),
            ID_SHA_384 => Sha384::digest(&self.signed_attrs).to_vec(),
            ID_SHA_512 => Sha512::digest(&self.signed_attrs).to_vec(),
            ID_SHA_224 => Sha224::digest(&self.signed_attrs).to_vec(),
            _ => bail!("Unsupported digest algorithm"),
        };

        match self.algo_signature {
            SECP_224_R_1 => {
                let key = VerifyingKey::<NistP224>::try_from(self.verifying_key)
                    .map_err(|_| eyre!("Invalid P224 public key"))?;
                let sig = Signature::<NistP224>::from_der(self.signature)
                    .wrap_err("parsing der signature")?;
                key.verify_prehash(&digest, &sig)
            }
            SECP_256_R_1 => {
                let key = VerifyingKey::<NistP256>::try_from(self.verifying_key)
                    .map_err(|_| eyre!("Invalid P256 public key"))?;
                let sig = Signature::<NistP256>::from_der(self.signature)
                    .wrap_err("parsing der signature")?;
                key.verify_prehash(&digest, &sig)
            }
            SECP_384_R_1 => {
                let key = VerifyingKey::<NistP384>::try_from(self.verifying_key)
                    .map_err(|_| eyre!("Invalid P384 public key"))?;
                let sig = Signature::<NistP384>::from_der(self.signature)
                    .wrap_err("parsing der signature")?;
                key.verify_prehash(&digest, &sig)
            }
            SECP_521_R_1 => {
                let key = VerifyingKey::<NistP521>::try_from(self.verifying_key)
                    .map_err(|_| eyre!("Invalid P521 public key"))?;
                let sig = Signature::<NistP521>::from_der(self.signature)
                    .wrap_err("parsing der signature")?;
                key.verify_prehash(&digest, &sig)
            }
            SECP_256_K_1 => {
                let key = VerifyingKey::<Secp256k1>::try_from(self.verifying_key)
                    .map_err(|_| eyre!("Invalid Secp256k1 public key"))?;
                let sig = Signature::<Secp256k1>::from_der(self.signature)
                    .wrap_err("parsing der signature")?;
                key.verify_prehash(&digest, &sig)
            }
            _ => bail!("Unsupported signature algorithm"),
        }
        .wrap_err("Signature verification failed")
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
