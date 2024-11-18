use crate::{bundle::VerificationBundle, pubkeys::Pubkey};
use cms::{cert::x509::attr::Attribute, signed_data::SignedAttributes};
use color_eyre::Result;
use const_oid::db::rfc5912::ID_SHA_256;
use der::{
    asn1::{OctetString, OctetStringRef, SetOfVec},
    Encode, Sequence, ValueOrd,
};
use digest::{
    const_oid::{AssociatedOid, ObjectIdentifier},
    Digest,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{X509Builder, X509Extension, X509NameBuilder},
};
use sha2::Sha256;
use smallvec::SmallVec;
use std::collections::BTreeSet;

pub const MRZ_FRODO: &[u8; 88] =
    b"P<GBRBAGGINS<<FRODO<<<<<<<<<<<<<<<<<<<<<<<<<P231458901GBR6709224M2209151ZE184226B<<<<<18";

fn mock_dg1_td3(mrz: &[u8; 88]) -> [u8; 93] {
    const MRZ_TD3_HEADER: [u8; 5] = [0x61, 0x5B, 0x5F, 0x1F, 0x58];
    let mut dg1 = [0u8; 93];
    dg1[..5].copy_from_slice(&MRZ_TD3_HEADER);

    dg1[5..].copy_from_slice(mrz);

    dg1
}

#[derive(Sequence, Debug)]
struct LDSSecurityObject {
    pub version: i32,
    pub digest_algorithm: DigestAlgorithm,
    pub dg_digests: Vec<DatagroupDigest>,
}

#[derive(Sequence, Debug)]
struct DigestAlgorithm {
    pub algorithm: ObjectIdentifier,
}

#[derive(Sequence, Debug, ValueOrd)]
struct DatagroupDigest {
    pub datagroup_number: u8,
    pub digest: OctetString,
}

fn hash_serialize_datagroup(
    m_digest: MockDigest,
    n: u8,
    datagroup_content: impl AsRef<[u8]>,
) -> DatagroupDigest {
    let digest = m_digest.digest(datagroup_content.as_ref());
    let hash_serialized = OctetString::new(digest).expect("digest serializes as octet string");
    DatagroupDigest {
        datagroup_number: n,
        digest: hash_serialized,
    }
}

fn mock_lds(m_digest: MockDigest, dg1: &[u8], include_dgs: BTreeSet<u8>) -> Vec<u8> {
    let mut dg_hashes = Vec::new();
    dg_hashes.push(hash_serialize_datagroup(m_digest, 1, dg1));
    include_dgs
        .into_iter()
        .filter(|n| *n != 1u8)
        .for_each(|n| dg_hashes.push(hash_serialize_datagroup(m_digest, n, [n])));

    let lds = LDSSecurityObject {
        version: 0,
        digest_algorithm: DigestAlgorithm {
            algorithm: m_digest.oid(),
        },
        dg_digests: dg_hashes,
    };

    lds.to_der().expect("infallible")
}

fn prepare_signed_attributes(lds_hash: &[u8]) -> Vec<u8> {
    const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
    const OID_MESSAGE_DIGEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
    const OID_ICAO_LDS_SOD: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.136.1.1.1");

    // Create attributes
    let content_type_attr = Attribute {
        oid: OID_CONTENT_TYPE,
        values: SetOfVec::try_from(vec![OID_ICAO_LDS_SOD.into()]).expect("infallible"),
    };

    let message_digest_attr = Attribute {
        oid: OID_MESSAGE_DIGEST,
        values: SetOfVec::try_from(vec![OctetStringRef::new(lds_hash)
            .expect("infallible")
            .into()])
        .expect("infallible"),
    };

    // Combine into SignedAttributes
    let signed_attrs = SignedAttributes::from(
        SetOfVec::try_from(vec![content_type_attr, message_digest_attr]).expect("infallible"),
    );
    signed_attrs.to_der().expect("infallible")
}

#[derive(Clone, Copy, Debug)]
pub struct MockDigest;

impl MockDigest {
    pub fn digest(&self, payload: &[u8]) -> Vec<u8> {
        Sha256::digest(payload).to_vec()
    }

    pub fn oid(&self) -> ObjectIdentifier {
        Sha256::OID
    }
}

fn mock_sign(signed_attrs_der: &[u8]) -> Result<MockSignOutput> {
    // 1. Create private key
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    // 2. Create certificate
    let mut builder = X509Builder::new()?;

    // Set version
    builder.set_version(2)?;

    // Set serial number
    let serial = BigNum::from_u32(1)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;

    // Set subject/issuer name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", "Mock CSCA")?;
    let name = name_builder.build();
    builder.set_issuer_name(&name)?;
    builder.set_subject_name(&name)?;

    // Set validity period
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Set public key
    builder.set_pubkey(&pkey)?;

    // Create extensions context first
    let ctx = builder.x509v3_context(None, None);

    // Create both extensions before attempting to append them
    #[allow(deprecated)]
    let ski_ext = X509Extension::new(None, Some(&ctx), "subjectKeyIdentifier", "hash")?;

    #[allow(deprecated)]
    let aki_ext = X509Extension::new(None, Some(&ctx), "authorityKeyIdentifier", "keyid")?;

    // Now append the extensions
    builder.append_extension(ski_ext)?;
    builder.append_extension(aki_ext)?;

    // Sign the certificate
    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = builder.build();

    // 3. Sign the payload using the private key
    let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(signed_attrs_der)?;
    let signature = signer.sign_to_vec()?;

    // 4. Return the struct with all required data
    let pubkey_der = pkey.public_key_to_der()?;
    let key_id = openssl::sha::sha256(&pubkey_der);

    Ok(MockSignOutput {
        document_signature: signature,
        cert_local_pubkey: Pubkey::try_from(pubkey_der.as_slice())?,
        cert_local_tbs: cert.to_der()?,
        cert_local_tbs_digest_algo: ID_SHA_256,
        cert_local_signature: cert.signature().as_slice().to_vec(),
        cert_master_subject_key_id: SmallVec::from_slice(&key_id[..20]),
        cert_master_pubkey: Pubkey::try_from(pubkey_der.as_slice())?,
    })
}

struct MockSignOutput {
    pub document_signature: Vec<u8>,
    pub cert_local_pubkey: Pubkey,
    pub cert_local_tbs: Vec<u8>,
    pub cert_local_tbs_digest_algo: ObjectIdentifier,
    pub cert_local_signature: Vec<u8>,
    pub cert_master_subject_key_id: SmallVec<[u8; 20]>,
    pub cert_master_pubkey: Pubkey,
}

pub fn mock_verification_bundle(mrz: &[u8; 88]) -> Result<VerificationBundle> {
    let m_digest = MockDigest;
    let dg1 = mock_dg1_td3(mrz);
    let lds = mock_lds(m_digest, &dg1, BTreeSet::from([1, 2, 3, 11, 12, 14]));
    let signed_attrs = prepare_signed_attributes(&m_digest.digest(&lds));
    let s = mock_sign(&signed_attrs)?;
    Ok(VerificationBundle {
        dg1: SmallVec::from_slice(&dg1),
        lds,
        signed_attrs: signed_attrs.into(),
        digest_algo: m_digest.oid(),
        document_signature: s.document_signature,
        cert_local_pubkey: s.cert_local_pubkey,
        cert_local_tbs: s.cert_local_tbs,
        cert_local_tbs_digest_algo: s.cert_local_tbs_digest_algo,
        cert_local_signature: s.cert_local_signature,
        cert_master_subject_key_id: s.cert_master_subject_key_id,
        cert_master_pubkey: s.cert_master_pubkey,
    })
}
