use crate::{
    bundle::VerificationBundle,
    bundle_signature::{Signature, SignatureEc, SignatureRsaPkcs},
    dg1::DG1Variant,
    pubkeys::{ClonableBigNum, Pubkey, PubkeyEC, PubkeyRSA},
};
use cms::{cert::x509::attr::Attribute, signed_data::SignedAttributes};
use color_eyre::{
    eyre::{eyre, ContextCompat},
    Result,
};
use der::{
    asn1::{OctetString, OctetStringRef, SetOfVec},
    Decode, Encode, Sequence, ValueOrd,
};
use digest::{
    const_oid::{AssociatedOid, ObjectIdentifier},
    Digest,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509Builder, X509NameBuilder},
};
use smallvec::SmallVec;
use std::collections::BTreeSet;

pub const MRZ_FRODO: &[u8; 88] =
    b"P<GBRBAGGINS<<FRODO<<<<<<<<<<<<<<<<<<<<<<<<<P231458901GBR6709224M2209151ZE184226B<<<<<18";

/// Enum to represent the master private key loaded from a PEM file
pub enum MasterPrivateKey {
    RSA(Rsa<Private>),
    EC(EcKey<Private>),
}

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

fn hash_serialize_datagroup<D>(n: u8, datagroup_content: impl AsRef<[u8]>) -> DatagroupDigest
where
    D: Digest,
{
    let digest = D::digest(datagroup_content.as_ref());
    let hash_serialized =
        OctetString::new(digest.as_ref()).expect("digest serializes as octet string");
    DatagroupDigest {
        datagroup_number: n,
        digest: hash_serialized,
    }
}

fn mock_lds<D>(dg1: &[u8], include_dgs: &BTreeSet<u8>) -> Vec<u8>
where
    D: Digest + AssociatedOid,
{
    let mut dg_hashes = Vec::new();
    dg_hashes.push(hash_serialize_datagroup::<D>(1, dg1));
    include_dgs
        .iter()
        .filter(|n| **n != 1u8)
        .for_each(|n| dg_hashes.push(hash_serialize_datagroup::<D>(*n, [*n])));

    let lds = LDSSecurityObject {
        version: 0,
        digest_algorithm: DigestAlgorithm { algorithm: D::OID },
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

struct MockTail {
    document_signature: Signature,
    cert_local_pubkey: Pubkey,
    cert_local_tbs: Vec<u8>,
    cert_local_tbs_digest_algo: Nid,
    cert_local_signature: Signature,
    cert_master_pubkey: Pubkey,
}

fn mock_tail_with_ec_master(
    signed_attrs_der: &[u8],
    digest_nid: Nid,
    master_key: &EcKey<Private>,
) -> Result<MockTail> {
    let digest = MessageDigest::from_nid(digest_nid).wrap_err("Invalid digest nid")?;

    // Extract the curve from the master key
    let group = EcGroup::from_curve_name(
        master_key
            .group()
            .curve_name()
            .ok_or_else(|| eyre!("Failed to get curve name from master key"))?,
    )?;

    // Create PKey from master key for signing
    let csca_pkey = PKey::from_ec_key(master_key.clone())?;

    // Generate a new key for document signer
    let ds_key = EcKey::generate(&group)?;
    let ds_pkey = PKey::from_ec_key(ds_key.clone())?;

    // Create self-signed certificate for document signer
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    let serial = BigNum::from_u32(1)?;
    let serial_ref = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial_ref)?;

    // Set 1 year validity period
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "Document Signer")?;
    let name = name.build();
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&ds_pkey)?;
    builder.sign(&csca_pkey, digest)?;

    let cert = builder.build();

    // Extract the TBS (to-be-signed) portion of the certificate for verification
    let tbs_cert_der = {
        let cert_serialized = cert.to_der()?;
        let cert_parsed = x509_cert::Certificate::from_der(&cert_serialized)?;
        cert_parsed.tbs_certificate.to_der()?
    };

    let cert_signature = cert.signature().as_slice().to_vec();

    // Sign the document attributes with the DS key
    let document_signature = {
        let mut signer = openssl::sign::Signer::new(digest, &ds_pkey)?;
        signer.update(signed_attrs_der)?;
        signer.sign_to_vec()?
    };

    // Extract public key coordinates for verification
    let mut ctx = BigNumContext::new()?;
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;

    master_key
        .public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
    let encoded: SmallVec<_> = master_key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .expect("we have the pubkey")
        .into();
    let csca_pubkey = Pubkey::EC(PubkeyEC {
        curve: master_key.group().curve_name().unwrap(),
        x: ClonableBigNum::from(x),
        y: ClonableBigNum::from(y),
        encoded,
    });

    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    ds_key
        .public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
    let encoded: SmallVec<_> = ds_key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .expect("we created the pubkey")
        .into();
    let ds_pubkey = Pubkey::EC(PubkeyEC {
        curve: master_key.group().curve_name().unwrap(),
        x: ClonableBigNum::from(x),
        y: ClonableBigNum::from(y),
        encoded,
    });

    Ok(MockTail {
        document_signature: Signature::Ec(SignatureEc::try_from(&document_signature[..])?),
        cert_local_pubkey: ds_pubkey,
        cert_local_tbs: tbs_cert_der,
        cert_local_tbs_digest_algo: digest_nid,
        cert_local_signature: Signature::Ec(SignatureEc::try_from(&cert_signature[..])?),
        cert_master_pubkey: csca_pubkey,
    })
}

fn mock_tail_with_rsa_master(
    signed_attrs_der: &[u8],
    digest_nid: Nid,
    master_key: &Rsa<Private>,
) -> Result<MockTail> {
    let digest = MessageDigest::from_nid(digest_nid).wrap_err("Invalid digest nid")?;

    // Extract the exponent from the master key
    let exponent = master_key.e().to_owned()?;

    // Create PKey from master key for signing
    let csca_pkey = PKey::from_rsa(master_key.clone())?;

    // Generate a new key for document signer with the same exponent
    let ds_key = Rsa::generate_with_e(master_key.size() * 8, &exponent)?;
    let ds_pkey = PKey::from_rsa(ds_key.clone())?;

    let clonable_exp = ClonableBigNum::from(exponent);

    // Create self-signed certificate for document signer
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    let serial = BigNum::from_u32(1)?;
    let serial_ref = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial_ref)?;

    // Set 1 year validity period
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "Document Signer")?;
    let name = name.build();
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&ds_pkey)?;
    builder.sign(&csca_pkey, digest)?;

    let cert = builder.build();

    // Extract the TBS (to-be-signed) portion of the certificate for verification
    let tbs_cert_der = {
        let cert_serialized = cert.to_der()?;
        let cert_parsed = x509_cert::Certificate::from_der(&cert_serialized)?;
        cert_parsed.tbs_certificate.to_der()?
    };

    let cert_signature = cert.signature().as_slice().to_vec();

    // Sign the document attributes with the DS key
    let document_signature = {
        let mut signer = openssl::sign::Signer::new(digest, &ds_pkey)?;
        signer.update(signed_attrs_der)?;
        signer.sign_to_vec()?
    };

    // Extract public key for verification
    let encoded: SmallVec<_> = master_key
        .public_key_to_der()
        .expect("we have this key")
        .into();
    let csca_pubkey = Pubkey::RSA(PubkeyRSA {
        modulus: ClonableBigNum::from(master_key.n().to_owned()?),
        exponent: clonable_exp.clone(),
        encoded,
    });

    let encoded: SmallVec<_> = ds_key
        .public_key_to_der()
        .expect("we created this key")
        .into();
    let ds_pubkey = Pubkey::RSA(PubkeyRSA {
        modulus: ClonableBigNum::from(ds_key.n().to_owned()?),
        exponent: clonable_exp,
        encoded,
    });

    Ok(MockTail {
        document_signature: Signature::RsaPkcs(SignatureRsaPkcs {
            signature: document_signature,
            message_hash_algorithm: digest_nid,
        }),
        cert_local_pubkey: ds_pubkey,
        cert_local_tbs: tbs_cert_der,
        cert_local_tbs_digest_algo: digest_nid,
        cert_local_signature: Signature::RsaPkcs(SignatureRsaPkcs {
            signature: cert_signature,
            message_hash_algorithm: digest_nid,
        }),
        cert_master_pubkey: csca_pubkey,
    })
}

pub struct MockConfig {
    pub mrz: [u8; 88],
    pub dgs: BTreeSet<u8>,
    pub digest_algo_head: Nid,
    pub digest_algo_tail: Nid,
    pub master_key: MasterPrivateKey,
}

impl MockConfig {
    fn mock_head<D>(&self) -> ([u8; 93], Vec<u8>, Vec<u8>)
    where
        D: Digest + AssociatedOid,
    {
        let dg1 = mock_dg1_td3(&self.mrz);
        let lds = mock_lds::<D>(&dg1, &self.dgs);
        let signed_attrs = prepare_signed_attributes(&D::digest(&lds));
        (dg1, lds, signed_attrs)
    }

    fn mock_tail(&self, signed_attrs: &[u8]) -> Result<MockTail> {
        match &self.master_key {
            MasterPrivateKey::EC(ec_key) => {
                mock_tail_with_ec_master(signed_attrs, self.digest_algo_tail, ec_key)
            }
            MasterPrivateKey::RSA(rsa_key) => {
                mock_tail_with_rsa_master(signed_attrs, self.digest_algo_tail, rsa_key)
            }
        }
    }

    pub fn mock(&self) -> Result<VerificationBundle> {
        let (dg1, lds, signed_attrs) = match self.digest_algo_head {
            Nid::SHA224 => self.mock_head::<sha2::Sha224>(),
            Nid::SHA256 => self.mock_head::<sha2::Sha256>(),
            Nid::SHA384 => self.mock_head::<sha2::Sha384>(),
            Nid::SHA512 => self.mock_head::<sha2::Sha512>(),
            _ => return Err(eyre!("Unsupported digest algorithm")),
        };
        let tail = self.mock_tail(&signed_attrs)?;

        Ok(VerificationBundle {
            dg1: SmallVec::from_slice(&dg1),
            dg1_variant: DG1Variant::TD3,
            lds,
            signed_attrs: signed_attrs.into(),
            digest_algo: self.digest_algo_head,
            document_signature: tail.document_signature,
            cert_local_pubkey: tail.cert_local_pubkey,
            cert_local_tbs: tail.cert_local_tbs,
            cert_local_tbs_digest_algo: tail.cert_local_tbs_digest_algo,
            cert_local_signature: tail.cert_local_signature,
            cert_master_subject_key_id: None,
            cert_master_pubkey: tail.cert_master_pubkey,
        })
    }
}
