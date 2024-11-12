use cms::signed_data::{EncapsulatedContentInfo, SignedAttributes};
use cms::{content_info::ContentInfo, signed_data::SignedData};
use color_eyre::eyre::{bail, Context, ContextCompat, Error, Result};
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{AnyRef, Decode, Encode, SliceReader};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

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

pub fn extract_signed_attrs(sod: &SignedData) -> Result<Vec<u8>> {
    let signer_infos = sod.signer_infos.0.as_ref();
    let signer_info = signer_infos.first().wrap_err("at least one signer info")?;
    let signed_attrs: &SignedAttributes = signer_info
        .signed_attrs
        .as_ref()
        .wrap_err("signed attrs not present")?;

    Ok(signed_attrs.to_der().expect("infallible"))
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
        let signed_attrs = extract_signed_attrs(&sod)?;
        Ok(PassportProvable {
            dg1: scan.dg1,
            lds,
            signed_attrs,
        })
    }
}
