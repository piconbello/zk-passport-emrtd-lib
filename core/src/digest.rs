use color_eyre::{eyre::eyre, Result};
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
use sha2::Digest;
use smallvec::SmallVec;

#[derive(Clone, Copy, Debug)]
pub enum Sha2 {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}
use openssl::{hash::MessageDigest, nid::Nid};

impl Sha2 {
    pub fn digest(&self, payload: impl AsRef<[u8]>) -> SmallVec<[u8; 64]> {
        match &self {
            Sha2::Sha224 => {
                let result = sha2::Sha224::digest(payload);
                SmallVec::from_slice(&result[..])
            }
            Sha2::Sha256 => {
                let result = sha2::Sha256::digest(payload);
                SmallVec::from_slice(&result[..])
            }
            Sha2::Sha384 => {
                let result = sha2::Sha384::digest(payload);
                SmallVec::from_slice(&result[..])
            }
            Sha2::Sha512 => {
                let result = sha2::Sha512::digest(payload);
                SmallVec::from_slice(&result[..])
            }
        }
    }

    pub fn from_signature_algo_pair_oid(pair: &ObjectIdentifier) -> Result<Self> {
        match *pair {
            ECDSA_WITH_SHA_224 => Ok(Self::Sha224),
            ECDSA_WITH_SHA_256 => Ok(Self::Sha256),
            ECDSA_WITH_SHA_384 => Ok(Self::Sha384),
            ECDSA_WITH_SHA_512 => Ok(Self::Sha512),
            SHA_224_WITH_RSA_ENCRYPTION => Ok(Self::Sha224),
            SHA_256_WITH_RSA_ENCRYPTION => Ok(Self::Sha256),
            SHA_384_WITH_RSA_ENCRYPTION => Ok(Self::Sha384),
            SHA_512_WITH_RSA_ENCRYPTION => Ok(Self::Sha512),
            _ => Err(eyre!("unsupported signature algo {:?}", DB.by_oid(pair))),
        }
    }

    pub fn from_digest_algo_oid(oid: &ObjectIdentifier) -> Result<Self> {
        match *oid {
            ID_SHA_224 => Ok(Self::Sha224),
            ID_SHA_256 => Ok(Self::Sha256),
            ID_SHA_384 => Ok(Self::Sha384),
            ID_SHA_512 => Ok(Self::Sha512),
            _ => Err(eyre!("unsupported digest algo {:?}", DB.by_oid(oid))),
        }
    }

    pub fn to_nid(&self) -> Nid {
        match self {
            Self::Sha224 => Nid::SHA224,
            Self::Sha256 => Nid::SHA256,
            Self::Sha384 => Nid::SHA384,
            Self::Sha512 => Nid::SHA512,
        }
    }

    pub fn to_message_digest(&self) -> MessageDigest {
        match self {
            Self::Sha224 => MessageDigest::sha224(),
            Self::Sha256 => MessageDigest::sha256(),
            Self::Sha384 => MessageDigest::sha384(),
            Self::Sha512 => MessageDigest::sha512(),
        }
    }
}
