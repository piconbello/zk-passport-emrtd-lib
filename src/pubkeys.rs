use base64::{prelude::BASE64_STANDARD, Engine};
use color_eyre::eyre::{bail, Context, ContextCompat, Error};
use der::{asn1::BitString, Any, Encode};
use openssl::{
    bn::{BigNum, BigNumContext},
    nid::Nid,
    pkey::{Id, PKey},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use spki::SubjectPublicKeyInfo;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Pubkey {
    EC(PubkeyEC),
    RSA(PubkeyRSA),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PubkeyEC {
    #[serde(with = "nid_serialization")]
    pub curve: Nid,
    #[serde(with = "bignum_serialization")]
    pub x: BigNum,
    #[serde(with = "bignum_serialization")]
    pub y: BigNum,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PubkeyRSA {
    #[serde(with = "bignum_serialization")]
    pub modulus: BigNum,
    #[serde(with = "bignum_serialization")]
    pub exponent: BigNum,
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

                Ok(Self::EC(PubkeyEC { curve, x, y }))
            }
            Id::RSA => {
                let rsa = pkey.rsa()?;
                let n = rsa.n();
                let e = rsa.e();

                Ok(Self::RSA(PubkeyRSA {
                    modulus: n.to_owned()?,
                    exponent: e.to_owned()?,
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

// #[derive(Debug)]
// pub struct SerializableBigNum(pub BigNum);

// impl Serialize for SerializableBigNum {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         // Convert BigNum to bytes
//         let bytes = self.0.to_vec();

//         // Convert bytes to base64
//         let base64_str = BASE64_STANDARD.encode(bytes);

//         // Serialize the base64 string
//         serializer.serialize_str(&base64_str)
//     }
// }

// impl<'de> Deserialize<'de> for SerializableBigNum {
//     fn deserialize<D>(deserializer: D) -> Result<SerializableBigNum, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         use serde::de::Error;

//         // Deserialize as string first
//         let base64_str = String::deserialize(deserializer)?;

//         // Decode base64 to bytes
//         let bytes = BASE64_STANDARD.decode(base64_str).map_err(Error::custom)?;

//         // Convert bytes to BigNum
//         let bn = BigNum::from_slice(&bytes).map_err(Error::custom)?;

//         Ok(SerializableBigNum(bn))
//     }
// }
mod bignum_serialization {
    use super::*;

    pub fn serialize<S>(bignum: &BigNum, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = bignum.to_vec();
        let base64_str = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&base64_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigNum, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let base64_str = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD.decode(base64_str).map_err(Error::custom)?;
        BigNum::from_slice(&bytes).map_err(Error::custom)
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
