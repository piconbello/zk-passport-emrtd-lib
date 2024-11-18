use color_eyre::{
    eyre::{eyre, ContextCompat},
    Result,
};
use const_oid::{
    db::{
        rfc5912::{
            ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512,
            ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512, SHA_224_WITH_RSA_ENCRYPTION,
            SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
        },
        DB,
    },
    ObjectIdentifier,
};
use der::Encode;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use smallvec::SmallVec;

use crate::{
    document_components::{extract_authority_identifier_key, DocumentComponents},
    master_certs::MasterCert,
    pubkeys::Pubkey,
};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationBundle {
    #[serde_as(as = "Base64")]
    pub dg1: SmallVec<[u8; 128]>,
    #[serde_as(as = "Base64")]
    pub lds: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub signed_attrs: SmallVec<[u8; 128]>,
    #[serde(with = "object_identifier_serialization")]
    pub digest_algo: ObjectIdentifier,
    #[serde_as(as = "Base64")]
    pub document_signature: Vec<u8>,
    pub cert_local_pubkey: Pubkey,
    #[serde_as(as = "Base64")]
    pub cert_local_tbs: Vec<u8>,
    #[serde(with = "object_identifier_serialization")]
    pub cert_local_tbs_digest_algo: ObjectIdentifier,
    #[serde_as(as = "Base64")]
    pub cert_local_signature: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub cert_master_subject_key_id: SmallVec<[u8; 20]>,
    pub cert_master_pubkey: Pubkey,
}

impl VerificationBundle {
    pub fn bundle(components: &DocumentComponents, master_certs: &[MasterCert]) -> Result<Self> {
        let authority_key_identifier = extract_authority_identifier_key(components.certificate)?;
        let cert_master = master_certs
            .iter()
            .find(|cert| cert.subject_key_id == authority_key_identifier)
            .wrap_err("No matching master certificate found")?
            .clone();

        Ok(Self {
            dg1: SmallVec::from_slice(components.dg1),
            lds: components.lds.into(),
            signed_attrs: components.signed_attrs.to_der()?.into(),
            digest_algo: components.digest_algo,
            document_signature: components.document_signature.into(),
            cert_local_pubkey: Pubkey::try_from(
                &components
                    .certificate
                    .tbs_certificate
                    .subject_public_key_info,
            )?,
            cert_local_tbs: components.certificate.tbs_certificate.to_der()?,
            cert_local_tbs_digest_algo: signature_algo_pair_to_digest_algo(
                &components.certificate.signature_algorithm.oid,
            )?,
            cert_local_signature: components
                .certificate
                .signature
                .as_bytes()
                .wrap_err("cert local has signature")?
                .into(),
            cert_master_subject_key_id: cert_master.subject_key_id,
            cert_master_pubkey: cert_master.pubkey,
        })
    }
}

pub fn signature_algo_pair_to_digest_algo(pair: &ObjectIdentifier) -> Result<ObjectIdentifier> {
    match *pair {
        ECDSA_WITH_SHA_224 => Ok(ID_SHA_224),
        ECDSA_WITH_SHA_256 => Ok(ID_SHA_256),
        ECDSA_WITH_SHA_384 => Ok(ID_SHA_384),
        ECDSA_WITH_SHA_512 => Ok(ID_SHA_512),
        SHA_224_WITH_RSA_ENCRYPTION => Ok(ID_SHA_224),
        SHA_256_WITH_RSA_ENCRYPTION => Ok(ID_SHA_256),
        SHA_384_WITH_RSA_ENCRYPTION => Ok(ID_SHA_384),
        SHA_512_WITH_RSA_ENCRYPTION => Ok(ID_SHA_512),
        _ => Err(eyre!("unsupported signature algo {:?}", DB.by_oid(pair))),
    }
}

mod object_identifier_serialization {
    use const_oid::{db::DB, ObjectIdentifier};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(oid: &ObjectIdentifier, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Get the name from the DB using the OID
        let name = DB
            .by_oid(oid)
            .ok_or_else(|| serde::ser::Error::custom("Unknown OID"))?;
        serializer.serialize_str(name)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ObjectIdentifier, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        // Deserialize the string name
        let name = String::deserialize(deserializer)?;

        // Look up the OID by name in the DB
        DB.by_name(&name)
            .ok_or_else(|| Error::custom("Unknown OID name"))
            .map(|oid| oid.to_owned())
    }
}
