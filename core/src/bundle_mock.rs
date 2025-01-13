use crate::{
    bundle::{Signature, SignatureEC, VerificationBundle},
    pubkeys::{ClonableBigNum, Pubkey, PubkeyEC},
};
use base64::{prelude::BASE64_STANDARD, Engine};
use cms::{cert::x509::attr::Attribute, signed_data::SignedAttributes};
use color_eyre::Result;
use const_oid::db::rfc5912::ID_SHA_256;
use der::{
    asn1::{OctetString, OctetStringRef, SetOfVec},
    Decode, Encode, Sequence, ValueOrd,
};
use digest::{
    const_oid::{AssociatedOid, ObjectIdentifier},
    Digest,
};
use openssl::{bn::BigNum, nid::Nid};
use rand::rngs::OsRng;
use sha2::Sha256;
use smallvec::SmallVec;
use std::{collections::BTreeSet, str::FromStr};
use x509_cert::certificate::CertificateInner;

pub const MRZ_FRODO: &[u8; 88] =
    b"P<GBRBAGGINS<<FRODO<<<<<<<<<<<<<<<<<<<<<<<<<P231458901GBR6709224M2209151ZE184226B<<<<<18";
const SECP_256_K_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

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

fn mock_lds(m_digest: MockDigest, dg1: &[u8], include_dgs: &BTreeSet<u8>) -> Vec<u8> {
    let mut dg_hashes = Vec::new();
    dg_hashes.push(hash_serialize_datagroup(m_digest, 1, dg1));
    include_dgs
        .iter()
        .filter(|n| **n != 1u8)
        .for_each(|n| dg_hashes.push(hash_serialize_datagroup(m_digest, *n, [*n])));

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
    use der::asn1::BitString;
    use k256::ecdsa::{signature::Signer, DerSignature, SigningKey, VerifyingKey};
    use std::time::Duration;
    use x509_cert::{
        builder::{Builder, CertificateBuilder, Profile},
        ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier},
        name::Name,
        serial_number::SerialNumber,
        spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
        time::Validity,
    };

    // Generate CSCA (master) key pair
    let csca_secret_key = SigningKey::random(&mut OsRng);
    let csca_public_key = VerifyingKey::from(&csca_secret_key);
    let csca_key_id: Vec<u8> = Sha256::digest(csca_public_key.to_encoded_point(false).as_bytes())
        .as_slice()
        .into();

    // Generate DS (document signer) key pair
    let ds_secret_key = SigningKey::random(&mut OsRng);
    let ds_public_key = VerifyingKey::from(&ds_secret_key);
    let ds_key_id: Vec<u8> = Sha256::digest(ds_public_key.to_encoded_point(false).as_bytes())
        .as_slice()
        .into();

    // Create DS certificate
    let serial_number = SerialNumber::new(&[1]).unwrap();
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60))?;
    let subject = Name::from_str("CN=Document Signer")?;
    let issuer = Name::from_str("CN=Country Signing CA")?;

    // Create SPKI from DS public key
    let ds_spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"), // id-ecPublicKey
            parameters: Some(der::Any::from_der(&SECP_256_K_1.to_der()?)?),
        },
        subject_public_key: BitString::from_bytes(
            ds_public_key.to_encoded_point(false).as_bytes(),
        )?,
    };

    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: issuer.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        serial_number,
        validity,
        subject,
        ds_spki,
        &csca_secret_key,
    )?;

    // Add extensions
    builder.add_extension(&SubjectKeyIdentifier(OctetString::new(ds_key_id.clone())?))?;
    builder.add_extension(&AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::new(csca_key_id.clone())?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    })?;
    builder.add_extension(&BasicConstraints {
        ca: false,
        path_len_constraint: None,
    })?;

    // Build and sign certificate
    let local_cert: CertificateInner = builder.build::<k256::ecdsa::DerSignature>()?;
    let tbs_cert_der = local_cert.tbs_certificate.to_der()?;

    // Sign TBS certificate with CSCA key
    let cert_signature: DerSignature = csca_secret_key.sign(&tbs_cert_der);
    let cert_signature_der = cert_signature.to_der()?;
    let cert_signature = Signature::EC(SignatureEC::try_from(cert_signature_der.as_slice())?);

    // Sign document with DS key
    let document_signature: DerSignature = ds_secret_key.sign(signed_attrs_der);
    let document_signature_der = document_signature.to_der()?;
    eprintln!(
        "doc sign base64 {}",
        BASE64_STANDARD.encode(&document_signature_der)
    );
    let document_signature =
        Signature::EC(SignatureEC::try_from(document_signature_der.as_slice())?);

    // // Convert public keys to our Pubkey format
    // let csca_pubkey = Pubkey::EC(PubkeyEC {
    //     curve: Nid::X9_62_PRIME256V1,
    //     x: BigNum::from_slice(&csca_public_key.to_encoded_point(false).x().unwrap())?.into(),
    //     y: BigNum::from_slice(&csca_public_key.to_encoded_point(false).y().unwrap())?.into(),
    // });

    // let ds_pubkey = Pubkey::EC(PubkeyEC {
    //     curve: Nid::X9_62_PRIME256V1,
    //     x: BigNum::from_slice(&ds_public_key.to_encoded_point(false).x().unwrap())?.into(),
    //     y: BigNum::from_slice(&ds_public_key.to_encoded_point(false).y().unwrap())?.into(),
    // });
    // Convert public keys to our Pubkey format
    let csca_pubkey = Pubkey::EC(PubkeyEC {
        curve: Nid::SECP256K1,
        x: ClonableBigNum::from(BigNum::from_slice(
            csca_public_key.to_encoded_point(false).x().unwrap(),
        )?),
        y: ClonableBigNum::from(BigNum::from_slice(
            csca_public_key.to_encoded_point(false).y().unwrap(),
        )?),
    });

    let ds_pubkey = Pubkey::EC(PubkeyEC {
        curve: Nid::SECP256K1,
        x: ClonableBigNum::from(BigNum::from_slice(
            ds_public_key.to_encoded_point(false).x().unwrap(),
        )?),
        y: ClonableBigNum::from(BigNum::from_slice(
            ds_public_key.to_encoded_point(false).y().unwrap(),
        )?),
    });

    Ok(MockSignOutput {
        document_signature,
        cert_local_pubkey: ds_pubkey,
        cert_local_tbs: tbs_cert_der,
        cert_local_tbs_digest_algo: ID_SHA_256,
        cert_local_signature: cert_signature,
        cert_master_subject_key_id: SmallVec::from_slice(&csca_key_id),
        cert_master_pubkey: csca_pubkey,
    })
}

struct MockSignOutput {
    pub document_signature: Signature,
    pub cert_local_pubkey: Pubkey,
    pub cert_local_tbs: Vec<u8>,
    pub cert_local_tbs_digest_algo: ObjectIdentifier,
    pub cert_local_signature: Signature,
    pub cert_master_subject_key_id: SmallVec<[u8; 20]>,
    pub cert_master_pubkey: Pubkey,
}

pub fn mock_verification_bundle(mrz: &[u8; 88], dgs: &BTreeSet<u8>) -> Result<VerificationBundle> {
    let m_digest = MockDigest;
    let dg1 = mock_dg1_td3(mrz);
    let lds = mock_lds(m_digest, &dg1, dgs);
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
