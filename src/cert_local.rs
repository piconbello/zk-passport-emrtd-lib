#![allow(non_snake_case)]
use cms::{
    cert::x509::{certificate::CertificateInner, ext::pkix::AuthorityKeyIdentifier},
    signed_data::{SignedAttributes, SignerInfo},
};
use color_eyre::{
    eyre::{bail, ensure, eyre, Context, ContextCompat, Error},
    Result,
};
use const_oid::{
    db::{
        rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
        rfc5912::{
            ECDSA_WITH_SHA_224, ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512,
            ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512, SECP_224_R_1, SECP_256_R_1,
            SECP_384_R_1, SECP_521_R_1, SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
            SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
        },
        DB,
    },
    AssociatedOid,
};
use der::{Decode, Encode, EncodeValue, Sequence};
use digest::{generic_array::ArrayLength, Digest};
use ecdsa::VerifyingKey;
use ecdsa::{der::MaxOverhead, signature::hazmat::PrehashVerifier, PrimeCurve, Signature};
use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    CurveArithmetic, FieldBytesSize,
};
use k256::Secp256k1;
use p224::NistP224;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use serde::Serialize;
use serde_with::{base64::Base64, serde_as};
use sha2::{Sha224, Sha256, Sha384, Sha512};
use smallvec::SmallVec;
use spki::ObjectIdentifier;
use std::ops::Add;

use crate::parse_ldif::extract_subject_identifier_key;

const SECP_256_K_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

#[serde_as]
#[derive(Debug, Serialize)]
pub struct PublicKeyCoords {
    #[serde_as(as = "Base64")]
    x: Vec<u8>,
    #[serde_as(as = "Base64")]
    y: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Serialize)]
pub struct SignatureComponents {
    #[serde_as(as = "Base64")]
    r: Vec<u8>,
    #[serde_as(as = "Base64")]
    s: Vec<u8>,
}

pub trait CurveOps {
    fn verify(&self, digest: &[u8]) -> Result<()>;
    fn public_key_coords(&self) -> PublicKeyCoords;
    fn signature_components(&self) -> SignatureComponents;
    fn oid(&self) -> ObjectIdentifier;
    fn algo_name(&self) -> &'static str;
}

struct CurveOpsImpl<C: PrimeCurve + CurveArithmetic> {
    verifying_key: VerifyingKey<C>,
    signature: Signature<C>,
}

impl<C> CurveOps for CurveOpsImpl<C>
where
    C: PrimeCurve + CurveArithmetic + AssociatedOid,
    VerifyingKey<C>: PrehashVerifier<Signature<C>>,
    <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
    <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
    <<C as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
{
    fn verify(&self, digest: &[u8]) -> Result<()> {
        self.verifying_key
            .verify_prehash(digest, &self.signature)
            .map_err(|e| eyre!("Verification failed: {}", e))
    }

    fn public_key_coords(&self) -> PublicKeyCoords
    where
        <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
    {
        let encoded_point = self.verifying_key.to_encoded_point(false);
        let x = encoded_point.x().unwrap().as_slice().to_vec();
        let y = encoded_point.y().unwrap().as_slice().to_vec();
        PublicKeyCoords { x, y }
    }

    fn signature_components(&self) -> SignatureComponents {
        let (r, s) = self.signature.split_bytes();
        SignatureComponents {
            r: r.to_vec(),
            s: s.to_vec(),
        }
    }

    fn oid(&self) -> ObjectIdentifier {
        <C as AssociatedOid>::OID
    }

    fn algo_name(&self) -> &'static str {
        DB.by_oid(&self.oid()).expect("unknown curve")
    }
}

impl<C> CurveOpsImpl<C>
where
    C: PrimeCurve + CurveArithmetic + AssociatedOid,
    VerifyingKey<C>: PrehashVerifier<Signature<C>> + for<'a> TryFrom<&'a [u8]>,
    ecdsa::der::MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
    <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
{
    pub fn from_bytes(verifying_key_der: &[u8], signature_der: &[u8]) -> Result<Box<dyn CurveOps>> {
        let verifying_key = VerifyingKey::<C>::try_from(verifying_key_der)
            .map_err(|_| eyre!("Failed to parse verifying key"))?;

        let signature = Signature::<C>::from_der(signature_der)?;

        Ok(Box::new(Self {
            verifying_key,
            signature,
        }))
    }
}

pub fn create_curve_ops(
    oid: &ObjectIdentifier,
    verifying_key_der: &[u8],
    signature_der: &[u8],
) -> Result<Box<dyn CurveOps>> {
    match *oid {
        SECP_224_R_1 => CurveOpsImpl::<NistP224>::from_bytes(verifying_key_der, signature_der),
        SECP_256_R_1 => CurveOpsImpl::<NistP256>::from_bytes(verifying_key_der, signature_der),
        SECP_384_R_1 => CurveOpsImpl::<NistP384>::from_bytes(verifying_key_der, signature_der),
        SECP_521_R_1 => CurveOpsImpl::<NistP521>::from_bytes(verifying_key_der, signature_der),
        SECP_256_K_1 => CurveOpsImpl::<Secp256k1>::from_bytes(verifying_key_der, signature_der),
        _ => bail!("Unsupported curve OID: {}", oid),
    }
}

pub enum DigestOps {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestOps {
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestOps::Sha224 => Sha224::digest(data).to_vec(),
            DigestOps::Sha256 => Sha256::digest(data).to_vec(),
            DigestOps::Sha384 => Sha384::digest(data).to_vec(),
            DigestOps::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            DigestOps::Sha224 => Sha224::OID,
            DigestOps::Sha256 => Sha256::OID,
            DigestOps::Sha384 => Sha384::OID,
            DigestOps::Sha512 => Sha512::OID,
        }
    }

    pub fn algo_name(&self) -> &'static str {
        DB.by_oid(&self.oid()).expect("unknown oid")
    }
}
impl TryFrom<ObjectIdentifier> for DigestOps {
    type Error = Error;

    fn try_from(oid: ObjectIdentifier) -> std::result::Result<Self, Self::Error> {
        match oid {
            ID_SHA_256 => Ok(Self::Sha256),
            ID_SHA_384 => Ok(Self::Sha384),
            ID_SHA_512 => Ok(Self::Sha512),
            ID_SHA_224 => Ok(Self::Sha224),
            _ => bail!("Unsupported digest algorithm"),
        }
    }
}

pub struct VerificationInput {
    pub payload: Vec<u8>,
    pub curve_ops: Box<dyn CurveOps>,
    pub hasher: DigestOps,
}

impl VerificationInput {
    pub fn verify(&self) -> Result<()> {
        let digest = self.hasher.digest(&self.payload);
        self.curve_ops.verify(&digest)
    }
}

pub fn extract_cert_local_verification_input(
    signer_info: &SignerInfo,
    cert: &CertificateInner,
) -> Result<VerificationInput> {
    let hasher = DigestOps::try_from(signer_info.digest_alg.oid)?;

    let algo_signature_oid = cert
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

    let curve_ops = create_curve_ops(&algo_signature_oid, verifying_key, signature)?;

    let signed_attrs_parsed: &SignedAttributes = signer_info
        .signed_attrs
        .as_ref()
        .wrap_err("signed attrs not present")?;
    let signed_attrs = signed_attrs_parsed.to_der()?;

    Ok(VerificationInput {
        payload: signed_attrs,
        curve_ops,
        hasher,
    })
}

fn deduce_algo_pair(cert_local: &CertificateInner) -> Result<(ObjectIdentifier, ObjectIdentifier)> {
    let digest_algo = match cert_local.signature_algorithm.oid {
        ECDSA_WITH_SHA_224 => ID_SHA_224,
        ECDSA_WITH_SHA_256 => ID_SHA_256,
        ECDSA_WITH_SHA_384 => ID_SHA_384,
        ECDSA_WITH_SHA_512 => ID_SHA_512,
        SHA_224_WITH_RSA_ENCRYPTION => ID_SHA_224,
        SHA_256_WITH_RSA_ENCRYPTION => ID_SHA_256,
        SHA_384_WITH_RSA_ENCRYPTION => ID_SHA_384,
        SHA_512_WITH_RSA_ENCRYPTION => ID_SHA_512,
        _ => bail!("unsupported digest algo"),
    };

    if !matches!(
        cert_local.signature_algorithm.oid,
        ECDSA_WITH_SHA_224 | ECDSA_WITH_SHA_256 | ECDSA_WITH_SHA_384 | ECDSA_WITH_SHA_512
    ) {
        bail!(
            "Unsupported signature algorithm {:?}",
            DB.by_oid(&cert_local.signature_algorithm.oid)
        );
    }

    let signature_len: u32 = cert_local
        .signature
        .value_len()
        .wrap_err("length of signature")?
        .into();

    let signature_algo = if signature_len <= 58 {
        SECP_224_R_1 // For NistP224
    } else if signature_len <= 72 {
        SECP_256_R_1 // For NistP256
    } else if signature_len <= 104 {
        SECP_384_R_1 // For NistP384
    } else if signature_len <= 140 {
        SECP_521_R_1 // For NistP521
    } else {
        bail!("Invalid signature length")
    };

    Ok((digest_algo, signature_algo))
}

#[derive(Sequence)]
struct AuthorityKeyIdentifierRaw {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    key_identifier: Vec<u8>,
}

fn extract_authorithy_key_identifier(cert_local: &CertificateInner) -> Result<SmallVec<[u8; 20]>> {
    let exts = cert_local
        .tbs_certificate
        .extensions
        .as_ref()
        .wrap_err("need extensions in cert")?;

    let ext = exts
        .iter()
        .find(|ext| ext.extn_id == ID_CE_AUTHORITY_KEY_IDENTIFIER)
        .wrap_err("need authority key extension")?;

    let aki = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()).wrap_err("cms")?;
    let ki = aki.key_identifier.wrap_err("need key identifier")?;
    let ki_len: u32 = ki.len().into();
    ensure!(ki_len == 20u32, "key identifier is 20 bytes");
    Ok(ki.as_bytes().into())
}

pub fn extract_cert_master_verification_input(
    cert_local: &CertificateInner,
    master_certs: &[CertificateInner],
) -> Result<VerificationInput> {
    let payload = cert_local
        .tbs_certificate
        .to_der()
        .expect("always serializes");

    let (digest_algo, sign_algo) = deduce_algo_pair(cert_local).wrap_err("deducing algo pair")?;

    let signature = cert_local
        .signature
        .as_bytes()
        .wrap_err("cert must have signature")?;

    let auth_key_identifier =
        extract_authorithy_key_identifier(cert_local).wrap_err("extracting key identifier")?;

    let pubkey_der_s_of_matching_certs: Result<Vec<Vec<u8>>> = master_certs
        .iter()
        .filter_map(|cert| match extract_subject_identifier_key(cert) {
            Ok(subject_key) => {
                let public_key_der = cert
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes()
                    .to_vec();

                if subject_key == auth_key_identifier {
                    Some(Ok(public_key_der))
                } else {
                    None
                }
            }
            Err(e) => Some(Err(e)),
        })
        .collect();

    let pubkey_der_s_of_matching_certs =
        pubkey_der_s_of_matching_certs.wrap_err("matching master pubkey error")?;

    let curve_ops = pubkey_der_s_of_matching_certs
        .iter()
        .filter_map(
            |pubkey_der| match create_curve_ops(&sign_algo, pubkey_der, signature) {
                Ok(ops) => Some(ops),
                Err(_) => None,
            },
        )
        .next()
        .wrap_err("no matching master cert pubkey")?;

    let hasher = DigestOps::try_from(digest_algo)?;

    Ok(VerificationInput {
        payload,
        curve_ops,
        hasher,
    })
}
