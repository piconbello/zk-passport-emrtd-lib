use base64::{prelude::BASE64_STANDARD, Engine};
use color_eyre::eyre::{eyre, Context, ContextCompat, Error, Result};
use const_oid::db::rfc5912;
use der::{asn1::BitString, Any, Decode};
use ecdsa::VerifyingKey;
use elliptic_curve::sec1::EncodedPoint;
use elliptic_curve::{
    generic_array::GenericArray,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    PublicKey,
};
use num_bigint_dig::BigUint;
use rsa::{pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts, RsaPublicKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use spki::{ObjectIdentifier, SubjectPublicKeyInfo};

const SECP_256_K_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Pubkey {
    EC(PubkeyEC),
    RSA(PubkeyRSA),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "curve")]
pub enum PubkeyEC {
    #[serde(rename = "secp256k1")]
    K256(AffineCoords),
    #[serde(rename = "secp224r1")]
    P224(AffineCoords),
    #[serde(rename = "secp256r1")]
    #[serde(alias = "prime256v1")]
    P256(AffineCoords),
    #[serde(rename = "secp384r1")]
    P384(AffineCoords),
    #[serde(rename = "secp521r1")]
    P521(AffineCoords),
    #[serde(rename = "brainpoolP384r1")]
    BP256(AffineCoords),
    #[serde(rename = "brainpoolP256r1")]
    BP384(AffineCoords),
    #[serde(rename = "brainpoolP512r1")]
    BP521(AffineCoords),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AffineCoords {
    #[serde(with = "biguint_serialization")]
    pub x: BigUint,
    #[serde(with = "biguint_serialization")]
    pub y: BigUint,
}

impl AffineCoords {
    pub fn from_public_key<C>(pubkey: &PublicKey<C>) -> Result<Self>
    where
        C: elliptic_curve::CurveArithmetic,
        C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        let point = pubkey.to_encoded_point(false);

        let x = BigUint::from_bytes_be(point.x().wrap_err("Missing x coordinate")?);
        let y = BigUint::from_bytes_be(point.y().wrap_err("Missing y coordinate")?);

        Ok(Self { x, y })
    }

    pub fn to_verifying_key<C>(&self) -> Result<VerifyingKey<C>>
    where
        C: elliptic_curve::CurveArithmetic + elliptic_curve::PrimeCurve,
        C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        let x: GenericArray<u8, C::FieldBytesSize> =
            GenericArray::clone_from_slice(self.x.to_bytes_be().as_slice());
        let y: GenericArray<u8, C::FieldBytesSize> =
            GenericArray::clone_from_slice(self.y.to_bytes_be().as_slice());
        // C::AffinePoint::from_encoded_point(point)
        let point = EncodedPoint::<C>::from_affine_coordinates(&x, &y, false);
        VerifyingKey::from_encoded_point(&point).wrap_err("Failed to create verifying key")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubkeyRSA {
    #[serde(with = "biguint_serialization")]
    pub modulus: BigUint,
    #[serde(with = "biguint_serialization")]
    pub exponent: BigUint,
}

impl TryFrom<&BitString> for PubkeyRSA {
    type Error = Error;

    fn try_from(value: &BitString) -> Result<Self> {
        let key = RsaPublicKey::from_pkcs1_der(value.raw_bytes())?;
        return Ok(Self {
            modulus: key.n().clone(),
            exponent: key.e().clone(),
        });
    }
}

impl TryFrom<&SubjectPublicKeyInfo<Any, BitString>> for Pubkey {
    type Error = Error;

    fn try_from(
        spki: &SubjectPublicKeyInfo<Any, BitString>,
    ) -> std::result::Result<Self, Self::Error> {
        match spki.algorithm.oid {
            rfc5912::SECP_224_R_1 => {
                let pubkey = p224::PublicKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
                    .wrap_err("parsing pubkey for p224")?;
                let coords =
                    AffineCoords::from_public_key(&pubkey).wrap_err("coords from pubkey p224")?;
                Ok(Self::EC(PubkeyEC::P224(coords)))
            }
            SECP_256_K_1 => {
                let pubkey = k256::PublicKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
                    .wrap_err("parsing pubkey for k256")?;
                let coords =
                    AffineCoords::from_public_key(&pubkey).wrap_err("coords from pubkey k256")?;
                Ok(Self::EC(PubkeyEC::K256(coords)))
            }
            rfc5912::SECP_256_R_1 => {
                let pubkey = p256::PublicKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
                    .wrap_err("parsing pubkey for p256")?;
                let coords =
                    AffineCoords::from_public_key(&pubkey).wrap_err("coords from pubkey p256")?;
                Ok(Self::EC(PubkeyEC::P256(coords)))
            }
            rfc5912::SECP_384_R_1 => {
                let pubkey = p384::PublicKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
                    .wrap_err("parsing pubkey for p384")?;
                let coords =
                    AffineCoords::from_public_key(&pubkey).wrap_err("coords from pubkey p384")?;
                Ok(Self::EC(PubkeyEC::P384(coords)))
            }
            rfc5912::SECP_521_R_1 => {
                let pubkey = p521::PublicKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
                    .wrap_err("parsing pubkey for p521")?;
                let coords =
                    AffineCoords::from_public_key(&pubkey).wrap_err("coords from pubkey p521")?;
                Ok(Self::EC(PubkeyEC::P521(coords)))
            }
            rfc5912::RSA_ENCRYPTION => {
                let key =
                    PubkeyRSA::try_from(&spki.subject_public_key).wrap_err("tried rsa parsing")?;
                Ok(Self::RSA(key))
            }
            rfc5912::ID_EC_PUBLIC_KEY => {
                let key_bytes = spki.subject_public_key.raw_bytes();

                // Try curves in order of common sizes
                // P-256/secp256r1
                if let Ok(pubkey) = p256::PublicKey::from_sec1_bytes(key_bytes) {
                    let coords = AffineCoords::from_public_key(&pubkey)?;
                    return Ok(Self::EC(PubkeyEC::P256(coords)));
                }
                // secp256k1
                if let Ok(pubkey) = k256::PublicKey::from_sec1_bytes(key_bytes) {
                    let coords = AffineCoords::from_public_key(&pubkey)?;
                    return Ok(Self::EC(PubkeyEC::K256(coords)));
                }
                // P-384
                if let Ok(pubkey) = p384::PublicKey::from_sec1_bytes(key_bytes) {
                    let coords = AffineCoords::from_public_key(&pubkey)?;
                    return Ok(Self::EC(PubkeyEC::P384(coords)));
                }
                // P-521
                if let Ok(pubkey) = p521::PublicKey::from_sec1_bytes(key_bytes) {
                    let coords = AffineCoords::from_public_key(&pubkey)?;
                    return Ok(Self::EC(PubkeyEC::P521(coords)));
                }
                use der::Encode;

                Err(eyre!(
                    "Failed to parse EC key with any known curve. SPKI DER: {}",
                    BASE64_STANDARD.encode(spki.to_der().wrap_err("spki serialization")?)
                ))
            }
            unsupported => Err(eyre!(
                "Unsupported algorithm for public key parsing: {:?}",
                unsupported.to_string()
            )),
        }
    }
}

impl TryFrom<&[u8]> for Pubkey {
    type Error = Error;

    fn try_from(spki_der: &[u8]) -> Result<Self> {
        let spki = SubjectPublicKeyInfo::from_der(spki_der).wrap_err("parsing spki")?;
        Self::try_from(&spki)
    }
}

mod biguint_serialization {
    use super::*;

    pub fn serialize<S>(bignum: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = bignum.to_bytes_be();
        let base64_str = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&base64_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let base64_str = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD.decode(base64_str).map_err(Error::custom)?;
        let bn = BigUint::from_bytes_be(&bytes);
        Ok(BigUint::from(bn))
    }
}
