use cms::signed_data::SignerInfo;
use color_eyre::eyre::{eyre, Context, ContextCompat, Error, Result};
use const_oid::{
    db::rfc5912::{
        ID_MGF_1, ID_RSASSA_PSS, SHA_224_WITH_RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION,
        SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
    },
    ObjectIdentifier,
};
use der::{Any, Decode, Encode, Sequence};
use openssl::nid::Nid;
use rsa::pkcs1::RsaPssParams;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use spki::AlgorithmIdentifier;
use x509_cert::certificate::{CertificateInner, Rfc5280};

use crate::common::nid_serialization;

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Signature {
    Ec(SignatureEc),
    RsaPss(SignatureRsaPss),
    RsaPkcs(SignatureRsaPkcs),
}
impl TryFrom<&SignerInfo> for Signature {
    type Error = Error;

    fn try_from(signer_info: &SignerInfo) -> Result<Self, Self::Error> {
        let algo_id = &signer_info.signature_algorithm;
        let signature_bytes = signer_info.signature.as_bytes();

        match algo_id.oid {
            ID_RSASSA_PSS => Ok(Self::RsaPss(
                parse_rsa_pss(algo_id, signature_bytes)
                    .wrap_err("Failed to parse RSASSA-PSS signature from SignerInfo")?,
            )),
            SHA_224_WITH_RSA_ENCRYPTION
            | SHA_256_WITH_RSA_ENCRYPTION
            | SHA_384_WITH_RSA_ENCRYPTION
            | SHA_512_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs(
                parse_rsa_pkcs(algo_id, signature_bytes)
                    .wrap_err("Failed to parse RSA PKCS#1 v1.5 signature from SignerInfo")?,
            )),
            // Add cases for EC signatures here if needed
            // OID_ECDSA_WITH_SHA256 => ... Self::Ec(...) ...
            _ => Err(eyre!(
                "Unsupported signature algorithm OID in SignerInfo: {}",
                algo_id.oid
            )),
        }
    }
}
impl TryFrom<&CertificateInner<Rfc5280>> for Signature {
    type Error = Error;

    fn try_from(cert: &CertificateInner<Rfc5280>) -> Result<Self, Self::Error> {
        let algo_id = &cert.signature_algorithm;
        let signature_bytes = cert
            .signature
            .as_bytes()
            .ok_or_else(|| eyre!("Certificate signature is not a primitive BIT STRING"))?; // Ensure signature is primitive octet string

        match algo_id.oid {
            ID_RSASSA_PSS => Ok(Self::RsaPss(
                parse_rsa_pss(algo_id, signature_bytes)
                    .wrap_err("Failed to parse RSASSA-PSS signature from Certificate")?,
            )),
            SHA_224_WITH_RSA_ENCRYPTION
            | SHA_256_WITH_RSA_ENCRYPTION
            | SHA_384_WITH_RSA_ENCRYPTION
            | SHA_512_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs(
                parse_rsa_pkcs(algo_id, signature_bytes)
                    .wrap_err("Failed to parse RSA PKCS#1 v1.5 signature from Certificate")?,
            )),
            // Add cases for EC signatures here if needed
            // OID_ECDSA_WITH_SHA256 => ... Self::Ec(...) ...
            _ => Err(eyre!(
                "Unsupported signature algorithm OID in Certificate: {}",
                algo_id.oid
            )),
        }
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureEc {
    #[serde_as(as = "Base64")]
    pub uncompressed: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub r: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub s: Vec<u8>,
}

impl TryFrom<&[u8]> for SignatureEc {
    type Error = Error;

    fn try_from(signature_der: &[u8]) -> std::result::Result<Self, Self::Error> {
        #[derive(Sequence)]
        pub struct Asn1Signature {
            r: der::asn1::Int,
            s: der::asn1::Int,
        }
        let signature_asn1: Asn1Signature = der::Decode::from_der(signature_der)?;
        Ok(Self {
            uncompressed: signature_der.into(),
            r: signature_asn1.r.as_bytes().into(),
            s: signature_asn1.s.as_bytes().into(),
        })
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureRsaPss {
    #[serde_as(as = "Base64")]
    pub signature: Vec<u8>,
    pub salt_size_bits: usize,
    #[serde(with = "nid_serialization")]
    pub message_hash_algorithm: Nid,
    #[serde(with = "nid_serialization")]
    pub mgf_hash_algorithm: Nid,
}

fn parse_rsa_pss(
    algo_id: &AlgorithmIdentifier<Any>,
    signature_bytes: &[u8],
) -> Result<SignatureRsaPss> {
    // Parameters are required for RSASSA-PSS
    let parameters_any = algo_id
        .parameters
        .as_ref()
        .ok_or_else(|| eyre!("RSASSA-PSS AlgorithmIdentifier missing parameters"))?;

    let params_der = parameters_any
        .to_der()
        .wrap_err("Failed to encode RSASSA-PSS parameters to DER")?;

    let parsed_params = RsaPssParams::from_der(&params_der)
        .wrap_err("Failed to parse RSASSA-PSS parameters DER")?;

    // Ensure the mask generation function is MGF1
    if parsed_params.mask_gen.oid != ID_MGF_1 {
        return Err(eyre!(
            "Unsupported mask generation function OID: {}",
            parsed_params.mask_gen.oid
        ));
    }

    // Extract the hash algorithm used within MGF1
    // MGF1 parameters *are* the AlgorithmIdentifier for the hash function.
    let mgf_params_alg_id = parsed_params
        .mask_gen
        .parameters // This is AlgorithmIdentifierRef<'a>
        .ok_or_else(|| eyre!("MGF1 parameters (inner hash algorithm) are missing"))?;

    let mgf_hash_nid = map_digest_oid_to_nid(&mgf_params_alg_id.oid)?;

    // Extract the main message hash algorithm OID from PSS parameters
    let message_hash_nid = map_digest_oid_to_nid(&parsed_params.hash.oid)?;

    // Extract Salt Length (salt_len is u8 representing bytes)
    let salt_len_bytes = parsed_params.salt_len;
    let salt_size_bits = (salt_len_bytes as usize) * 8;

    Ok(SignatureRsaPss {
        signature: signature_bytes.to_vec(),
        salt_size_bits,
        message_hash_algorithm: message_hash_nid,
        mgf_hash_algorithm: mgf_hash_nid,
    })
}

fn parse_rsa_pkcs(
    algo_id: &AlgorithmIdentifier<Any>,
    signature_bytes: &[u8],
) -> Result<SignatureRsaPkcs> {
    // The OID itself determines the hash algorithm for PKCS#1 v1.5 signature schemes.
    let message_hash_nid = map_digest_oid_to_nid(&algo_id.oid)?;

    Ok(SignatureRsaPkcs {
        signature: signature_bytes.to_vec(),
        message_hash_algorithm: message_hash_nid,
    })
}

impl TryFrom<&SignerInfo> for SignatureRsaPss {
    type Error = Error;

    fn try_from(signer_info: &SignerInfo) -> Result<Self, Self::Error> {
        // 1. Ensure the algorithm is RSASSA-PSS
        if signer_info.signature_algorithm.oid != ID_RSASSA_PSS {
            return Err(eyre!("SignerInfo algorithm is not RSASSA-PSS"));
        }

        // 2. Extract and parse the parameters
        let parameters_any = signer_info
            .signature_algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| eyre!("RSASSA-PSS AlgorithmIdentifier missing parameters"))?;

        let params_der = parameters_any
            .to_der()
            .wrap_err("Failed to encode parameters to DER")?;
        // dbg!(format!("PSS Params DER: {}", hex::encode(&params_der))); // Keep your debug print

        let parsed_params = RsaPssParams::from_der(&params_der)
            .wrap_err("Failed to parse RSASSA-PSS parameters DER")?;

        dbg!(parsed_params.hash);

        // 3. Extract MGF Hash Algorithm
        // Verify the mask generation function is mgf1
        if parsed_params.mask_gen.oid != ID_MGF_1 {
            return Err(eyre!(
                "Unsupported mask generation function OID: {}",
                parsed_params.mask_gen.oid
            ));
        }

        // The MGF parameters contain the hash algorithm identifier
        let mgf_params_alg_id = parsed_params
            .mask_gen
            .parameters // This is an Option<AlgorithmIdentifierRef<'a>> in pkcs1 v0.7+
            .ok_or_else(|| eyre!("MGF1 parameters (hash algorithm) are missing"))?;

        // The actual type inside AlgorithmIdentifier<AlgorithmIdentifierRef<'a>> might vary.
        // Let's assume it's AlgorithmIdentifierRef based on the pkcs1 definition.
        // mgf_params_alg_id here is AlgorithmIdentifierRef<'a>
        let mgf_hash_oid = mgf_params_alg_id.oid;

        let mgf_hash_nid = map_digest_oid_to_nid(&mgf_hash_oid)?;

        // 4. Extract Salt Length (in bytes from params, convert to bits)
        // salt_len is u8 in RsaPssParams
        let salt_len_bytes = parsed_params.salt_len;
        let salt_size_bits = (salt_len_bytes as usize) * 8;

        // 5. Extract the signature itself
        let signature_bytes = signer_info.signature.as_bytes().to_vec();

        let message_hash_nid = map_digest_oid_to_nid(&parsed_params.hash.oid)?;

        // 6. Construct the SignatureRsaPss struct
        Ok(SignatureRsaPss {
            signature: signature_bytes,
            salt_size_bits,
            message_hash_algorithm: message_hash_nid,
            mgf_hash_algorithm: mgf_hash_nid,
        })
    }
}

impl TryFrom<&CertificateInner<Rfc5280>> for SignatureRsaPss {
    type Error = Error;

    fn try_from(cert: &CertificateInner<Rfc5280>) -> Result<Self, Self::Error> {
        let algo_oid = cert.signature_algorithm.oid;

        if algo_oid != ID_RSASSA_PSS {
            return Err(eyre!("SignerInfo algorithm is not RSASSA-PSS"));
        }

        // Handle RSASSA-PSS signature
        let parameters_any = cert
            .signature_algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| eyre!("RSASSA-PSS AlgorithmIdentifier missing parameters"))?;

        let params_der = parameters_any
            .to_der()
            .wrap_err("Failed to encode parameters to DER")?;

        let parsed_params = RsaPssParams::from_der(&params_der)
            .wrap_err("Failed to parse RSASSA-PSS parameters DER")?;

        // Verify the mask generation function is mgf1
        if parsed_params.mask_gen.oid != ID_MGF_1 {
            return Err(eyre!(
                "Unsupported mask generation function OID: {}",
                parsed_params.mask_gen.oid
            ));
        }

        // Extract MGF Hash Algorithm
        let mgf_params_alg_id = parsed_params
            .mask_gen
            .parameters
            .ok_or_else(|| eyre!("MGF1 parameters (hash algorithm) are missing"))?;

        let mgf_hash_oid = mgf_params_alg_id.oid;
        let mgf_hash_nid = map_digest_oid_to_nid(&mgf_hash_oid)?;

        // Extract Salt Length
        let salt_len_bytes = parsed_params.salt_len;
        let salt_size_bits = (salt_len_bytes as usize) * 8;

        // Extract the signature itself
        let signature_bytes = cert
            .signature
            .as_bytes()
            .wrap_err("expect sign here")?
            .to_vec();

        let message_hash_nid = map_digest_oid_to_nid(&parsed_params.hash.oid)?;

        // Construct the SignatureRsaPss struct
        Ok(SignatureRsaPss {
            signature: signature_bytes,
            salt_size_bits,
            message_hash_algorithm: message_hash_nid,
            mgf_hash_algorithm: mgf_hash_nid,
        })
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureRsaPkcs {
    #[serde_as(as = "Base64")]
    pub signature: Vec<u8>,
    /// The message hash algorithm implied by the signature OID.
    #[serde(with = "nid_serialization")]
    pub message_hash_algorithm: Nid,
}

fn map_digest_oid_to_nid(oid: &ObjectIdentifier) -> Result<Nid> {
    crate::digest::Sha2::from_oid(oid)
        .map(|sha2_enum| sha2_enum.to_nid())
        .wrap_err_with(|| format!("Failed to map digest OID {} to NID", oid))
}
