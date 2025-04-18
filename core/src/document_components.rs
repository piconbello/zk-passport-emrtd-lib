use cms::{
    cert::x509::{certificate::CertificateInner, ext::pkix::AuthorityKeyIdentifier},
    content_info::ContentInfo,
    signed_data::{EncapsulatedContentInfo, SignedAttributes, SignedData, SignerInfo},
};
use color_eyre::{
    eyre::{bail, Context, ContextCompat},
    Result,
};
use const_oid::db::rfc5912::{ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_SUBJECT_KEY_IDENTIFIER};
use der::{asn1::OctetStringRef, AnyRef, Decode, SliceReader};
use smallvec::SmallVec;
use spki::ObjectIdentifier;
use x509_cert::ext::pkix::SubjectKeyIdentifier;

use crate::dg1::DG1Variant;

const OID_MRTD_SIGNATURE_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.136.1.1.1");

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

fn extract_digest_algo(sod: &SignedData) -> Result<ObjectIdentifier> {
    Ok(sod
        .digest_algorithms
        .as_ref()
        .first()
        .wrap_err("there must be one digest algorithm")?
        .oid)
}

fn extract_lds_from_econtent(enc_content: &EncapsulatedContentInfo) -> Result<&[u8]> {
    if enc_content.econtent_type != OID_MRTD_SIGNATURE_DATA {
        bail!("encapsulated content is not mrtd signature data");
    }

    let any = match &enc_content.econtent {
        None => bail!("encapsulated content does not contain data"),
        Some(any) => any,
    };

    let oc = any.decode_as::<OctetStringRef>()?;

    Ok(oc.as_bytes())
}

fn extract_signer_info(sod: &SignedData) -> Result<&SignerInfo> {
    sod.signer_infos
        .0
        .as_ref()
        .first()
        .wrap_err("there must be one signer info")
}

fn extract_signed_attrs(signer_info: &SignerInfo) -> Result<&SignedAttributes> {
    signer_info
        .signed_attrs
        .as_ref()
        .wrap_err("signed attrs not present")
}

fn extract_certificate(sod: &SignedData) -> Result<&CertificateInner> {
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

pub fn extract_authority_identifier_key(cert: &CertificateInner) -> Option<SmallVec<[u8; 20]>> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;

    let ext = exts
        .iter()
        .find(|ext| ext.extn_id == ID_CE_AUTHORITY_KEY_IDENTIFIER)?;

    let aki = match AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
        Ok(aki) => aki,
        Err(_) => return None,
    };

    let ki = aki.key_identifier?;
    Some(ki.as_bytes().into())
}

pub fn extract_subject_identifier_key(
    master_cert: &CertificateInner,
) -> Result<SmallVec<[u8; 20]>> {
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

pub struct DocumentComponents<'a> {
    pub dg1: &'a [u8],
    pub dg1_variant: DG1Variant,
    pub lds: &'a [u8],
    pub signed_attrs: &'a SignedAttributes,
    pub digest_algo: ObjectIdentifier,
    pub certificate: &'a CertificateInner,
    pub signer_info: &'a SignerInfo,
}

impl<'a> DocumentComponents<'a> {
    pub fn new(sod: &'a SignedData, dg1: &'a [u8], dg1_variant: DG1Variant) -> Result<Self> {
        let signer_info = extract_signer_info(sod)?;
        let certificate = extract_certificate(sod)?;
        Ok(Self {
            dg1,
            dg1_variant,
            lds: extract_lds_from_econtent(&sod.encap_content_info)?,
            signed_attrs: extract_signed_attrs(signer_info)?,
            digest_algo: extract_digest_algo(sod)?,
            certificate,
            signer_info,
        })
    }
}
