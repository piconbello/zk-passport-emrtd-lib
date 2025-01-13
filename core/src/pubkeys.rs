use std::ops::{Deref, DerefMut};

use base64::{prelude::BASE64_STANDARD, Engine};
use color_eyre::eyre::{bail, Context, ContextCompat, Error, Result};
use der::{asn1::BitString, Any, Encode};
use openssl::{
    bn::{BigNum, BigNumContext},
    nid::Nid,
    pkey::{Id, PKey},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use spki::SubjectPublicKeyInfo;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Pubkey {
    EC(PubkeyEC),
    RSA(PubkeyRSA),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubkeyEC {
    #[serde(with = "nid_serialization")]
    pub curve: Nid,
    #[serde(with = "clonable_bignum_serialization")]
    pub x: ClonableBigNum,
    #[serde(with = "clonable_bignum_serialization")]
    pub y: ClonableBigNum,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubkeyRSA {
    #[serde(with = "clonable_bignum_serialization")]
    pub modulus: ClonableBigNum,
    #[serde(with = "clonable_bignum_serialization")]
    pub exponent: ClonableBigNum,
}

impl TryFrom<&[u8]> for Pubkey {
    type Error = Error;

    fn try_from(spki_der: &[u8]) -> std::result::Result<Self, Self::Error> {
        let pkey = PKey::public_key_from_der(spki_der)?;

        match pkey.id() {
            Id::EC => {
                let ec_key = pkey.ec_key()?;
                let pub_key = ec_key.public_key();
                let group = ec_key.group();

                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;
                let mut ctx = BigNumContext::new()?;

                pub_key.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;
                let curve = group.curve_name().wrap_err("unknown curve")?;

                Ok(Self::EC(PubkeyEC {
                    curve,
                    x: x.into(),
                    y: y.into(),
                }))
            }
            Id::RSA => {
                let rsa = pkey.rsa()?;
                let n = rsa.n();
                let e = rsa.e();

                Ok(Self::RSA(PubkeyRSA {
                    modulus: n.to_owned()?.into(),
                    exponent: e.to_owned()?.into(),
                }))
            }
            _ => bail!("could not parse spki"),
        }
    }
}

impl TryFrom<&SubjectPublicKeyInfo<Any, BitString>> for Pubkey {
    type Error = Error;

    fn try_from(
        spki: &SubjectPublicKeyInfo<Any, BitString>,
    ) -> std::result::Result<Self, Self::Error> {
        let der = spki.to_der().wrap_err("spki should serialize")?;
        Pubkey::try_from(der.as_slice())
    }
}

mod clonable_bignum_serialization {
    use super::*;

    pub fn serialize<S>(bignum: &ClonableBigNum, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = bignum.to_vec();
        let base64_str = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&base64_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ClonableBigNum, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let base64_str = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD.decode(base64_str).map_err(Error::custom)?;
        let bn = BigNum::from_slice(&bytes).map_err(Error::custom)?;
        Ok(ClonableBigNum::from(bn))
    }
}

mod nid_serialization {
    use std::ffi::CString;

    use super::*;
    use serde::de::Error;

    pub fn serialize<S>(nid: &Nid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let short_name = nid.short_name().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(short_name)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Nid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        // Convert to CString for FFI
        let c_str = CString::new(name.clone())
            .map_err(|e| D::Error::custom(format!("Invalid string: {}", e)))?;

        // Use unsafe block to call OpenSSL's OBJ_sn2nid
        let nid = unsafe { openssl_sys::OBJ_sn2nid(c_str.as_ptr()) };

        if nid == 0 {
            return Err(D::Error::custom(format!("Unknown curve name: {}", name)));
        }

        Ok(Nid::from_raw(nid))
    }
}
#[derive(Debug)]
pub struct ClonableBigNum(BigNum);

impl Clone for ClonableBigNum {
    fn clone(&self) -> Self {
        let mut new = BigNum::new().expect("Failed to create BigNum");
        new.copy_from_slice(&self.0.to_vec())
            .expect("Failed to copy BigNum");
        ClonableBigNum(new)
    }
}

impl Deref for ClonableBigNum {
    type Target = BigNum;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ClonableBigNum {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// Add conversion methods
impl From<BigNum> for ClonableBigNum {
    fn from(bn: BigNum) -> Self {
        ClonableBigNum(bn)
    }
}
