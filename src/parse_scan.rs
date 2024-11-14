use cms::cert::x509::certificate::CertificateInner;
use cms::signed_data::{EncapsulatedContentInfo, SignedAttributes, SignerInfo};
use cms::{content_info::ContentInfo, signed_data::SignedData};
use color_eyre::eyre::{bail, Context, ContextCompat, Error, Result};
use const_oid::db::DB;
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{AnyRef, Decode, Encode, SliceReader};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

use crate::cert_local::{
    extract_passport_verification_input, PublicKeyCoords, SignatureComponents,
};
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

pub fn extract_digest_algo(sod: &SignedData) -> Result<ObjectIdentifier> {
    Ok(sod
        .digest_algorithms
        .as_ref()
        .first()
        .wrap_err("there must be one digest algorithm")?
        .oid)
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
    pub digest_algo: String,
    pub certificate_local: CertificateLocalProvable,
}

#[serde_as]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateLocalProvable {
    digest_algorithm: String,
    signature_algorithm: String,
    public_key: PublicKeyCoords,
    signature: SignatureComponents,
}

impl TryFrom<&PassportScan> for PassportProvable {
    type Error = Error;

    fn try_from(scan: &PassportScan) -> std::result::Result<Self, Self::Error> {
        let sod = parse_sod(&scan.sod)?;
        let lds = extract_lds_from_econtent(&sod.encap_content_info)?;
        let signer_info = extract_signer_info(&sod)?;
        let signed_attrs = extract_signed_attrs(signer_info)?;
        let digest_algo = extract_digest_algo(&sod)?;
        let digest_algo_name = DB.by_oid(&digest_algo).wrap_err("unknown digest algo")?;
        let certificate = extract_certificate(&sod)?;

        let passport_verification_input =
            extract_passport_verification_input(signer_info, certificate)?;

        let cert_local = CertificateLocalProvable {
            digest_algorithm: passport_verification_input.hasher.algo_name().into(),
            signature_algorithm: passport_verification_input.curve_ops.algo_name().into(),
            public_key: passport_verification_input.curve_ops.public_key_coords(),
            signature: passport_verification_input.curve_ops.signature_components(),
        };

        Ok(PassportProvable {
            dg1: scan.dg1,
            lds,
            signed_attrs,
            digest_algo: digest_algo_name.into(),
            certificate_local: cert_local,
        })
    }
}
