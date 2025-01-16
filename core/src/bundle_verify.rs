use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use crate::{
    bundle::{Asn1Signature, Signature, VerificationBundle},
    pubkeys_pure::{AffineCoords, Pubkey, PubkeyEC},
};
use color_eyre::eyre::{bail, eyre, Context, Result};
use const_oid::{
    db::{
        rfc5912::{ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512},
        DB,
    },
    AssociatedOid, ObjectIdentifier,
};
use der::Encode;
use ecdsa::signature::Verifier;
use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    FieldBytes,
};
use p224::NistP224;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use smallvec::SmallVec;

pub trait Verify {
    fn verify(&self) -> Result<()>;
}

impl Verify for VerificationBundle {
    fn verify(&self) -> Result<()> {
        // 1. Verify that digest of dg1 is in lds
        let dg1_digest = digest(&self.digest_algo, &self.dg1)?;
        if !self
            .lds
            .windows(dg1_digest.len())
            .any(|window| window == dg1_digest.as_slice())
        {
            return Err(eyre!("DG1 digest not found in LDS"));
        }

        // 2. Verify that digest of lds is in signed_attrs
        let lds_digest = digest(&self.digest_algo, &self.lds)?;
        if !self
            .signed_attrs
            .windows(lds_digest.len())
            .any(|window| window == lds_digest.as_slice())
        {
            return Err(eyre!("LDS digest not found in signed attributes"));
        }

        // 3. Verify that signed_attrs is signed by the local cert

        verify_signature(
            &self.signed_attrs,
            &self.document_signature,
            &self.cert_local_pubkey,
            &self.digest_algo,
        )
        .wrap_err("verifying signed_attrs and local cert")?;
        // let pkey = match &self.cert_local_pubkey {
        //     Pubkey::EC(ec) => {
        //         let group = openssl::ec::EcGroup::from_curve_name(ec.curve)?;
        //         let mut ctx = openssl::bn::BigNumContext::new()?;
        //         let mut point = openssl::ec::EcPoint::new(&group)?;
        //         point.set_affine_coordinates_gfp(&group, &ec.x, &ec.y, &mut ctx)?;

        //         let ec_key = openssl::ec::EcKey::from_public_key(&group, &point)?;
        //         PKey::from_ec_key(ec_key)?
        //     }
        //     Pubkey::RSA(rsa) => {
        //         let modulus = rsa.modulus.to_vec();
        //         let exponent = rsa.exponent.to_vec();
        //         let rsa_key = openssl::rsa::Rsa::from_public_components(
        //             openssl::bn::BigNum::from_slice(&modulus)?,
        //             openssl::bn::BigNum::from_slice(&exponent)?,
        //         )?;
        //         PKey::from_rsa(rsa_key)?
        //     }
        // };

        // 4. Verify that local cert is signed by the master cert
        verify_signature(
            &self.cert_local_tbs,
            &self.cert_local_signature,
            &self.cert_master_pubkey,
            &self.cert_local_tbs_digest_algo,
        )
        .wrap_err("verifying local cert and master cert")?;

        // let master_pkey = match &self.cert_master_pubkey {
        //     Pubkey::EC(ec) => {
        //         let group = openssl::ec::EcGroup::from_curve_name(ec.curve)?;
        //         let mut ctx = openssl::bn::BigNumContext::new()?;
        //         let mut point = openssl::ec::EcPoint::new(&group)?;
        //         point.set_affine_coordinates_gfp(&group, &ec.x, &ec.y, &mut ctx)?;

        //         let ec_key = openssl::ec::EcKey::from_public_key(&group, &point)?;
        //         PKey::from_ec_key(ec_key)?
        //     }
        //     Pubkey::RSA(rsa) => {
        //         let modulus = rsa.modulus.to_vec();
        //         let exponent = rsa.exponent.to_vec();
        //         let rsa_key = openssl::rsa::Rsa::from_public_components(
        //             openssl::bn::BigNum::from_slice(&modulus)?,
        //             openssl::bn::BigNum::from_slice(&exponent)?,
        //         )?;
        //         PKey::from_rsa(rsa_key)?
        //     }
        // };

        // verify_signature(
        //     &self.cert_local_tbs,
        //     &self.cert_local_signature,
        //     &master_pkey,
        //     &self.cert_local_tbs_digest_algo,
        // )
        // .wrap_err("verifying cert")?;

        Ok(())
    }
}

fn digest(algo: &ObjectIdentifier, data: &[u8]) -> Result<SmallVec<[u8; 64]>> {
    match *algo {
        ID_SHA_224 => Ok(Sha224::digest(data).as_slice().into()),
        ID_SHA_256 => Ok(Sha256::digest(data).as_slice().into()),
        ID_SHA_384 => Ok(Sha384::digest(data).as_slice().into()),
        ID_SHA_512 => Ok(Sha512::digest(data).as_slice().into()),
        _ => bail!("Unsupported digest algorithm, {:?}", DB.by_oid(algo)),
    }
}

fn verify_signature_ec<C, D>(
    message: &[u8],
    pubkey_coords: &AffineCoords,
    signature: ecdsa::Signature<C>,
) -> Result<()>
where
    C: elliptic_curve::CurveArithmetic + elliptic_curve::PrimeCurve,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
    D: Digest,
    ecdsa::VerifyingKey<C>: Verifier<ecdsa::Signature<C>>,
{
    let verifying_key = pubkey_coords.to_verifying_key::<C>()?;

    let digest = D::digest(message);

    // eprintln!("Signature: {}", BASE64_STANDARD.encode(signature.to_vec()));
    eprintln!("Digest: {}", BASE64_STANDARD.encode(&digest));
    eprintln!("Coords: {:?}", pubkey_coords);
    // eprintln!("Verifying key: {:?}", verifying_key.to_sec1_bytes());

    verifying_key
        .verify(&digest, &signature)
        .wrap_err("ECDSA verification failed")
}

fn verify_signature_rsa<D>(
    message: &[u8],
    public_key: &RsaPublicKey,
    signature: &[u8],
) -> Result<()>
where
    D: Digest + AssociatedOid,
{
    public_key
        .verify(Pkcs1v15Sign::new::<D>(), &D::digest(message), signature)
        .wrap_err("RSA verification failed")
}

fn verify_signature_with_digest<D>(
    message: &[u8],
    signature: &Signature,
    public_key: &Pubkey,
) -> Result<()>
where
    D: Digest + AssociatedOid,
{
    match (public_key, signature) {
        // P224
        (Pubkey::EC(PubkeyEC::P224(coords)), Signature::EC(sig)) => {
            let signature = sig
                .try_into()
                .wrap_err("ECDSA signature construction failed for p224")?;
            verify_signature_ec::<p224::NistP224, D>(message, coords, signature)
        }
        // P256
        (Pubkey::EC(PubkeyEC::P256(coords)), Signature::EC(sig)) => {
            let signature = sig
                .try_into()
                .wrap_err("ECDSA signature construction failed for p256")?;
            verify_signature_ec::<p256::NistP256, D>(message, coords, signature)
        }
        // P384
        (Pubkey::EC(PubkeyEC::P384(coords)), Signature::EC(sig)) => {
            let signature = sig
                .try_into()
                .wrap_err("ECDSA signature construction failed for p384")?;
            verify_signature_ec::<p384::NistP384, D>(message, coords, signature)
        }
        // P521
        (Pubkey::EC(PubkeyEC::P521(coords)), Signature::EC(sig)) => {
            todo!("p521 is weird");
            // let signature = sig
            //     .try_into()
            //     .wrap_err("ECDSA signature construction failed for p521")?;
            // verify_signature_ec::<p521::NistP521, D>(message, coords, signature)
        }
        // K256 (secp256k1)
        (Pubkey::EC(PubkeyEC::K256(coords)), Signature::EC(sig)) => {
            let signature = sig
                .try_into()
                .wrap_err("ECDSA signature construction failed for k256")?;
            verify_signature_ec::<k256::Secp256k1, D>(message, coords, signature)
        }
        // RSA
        (Pubkey::RSA(key), Signature::RSA(sig)) => {
            let public_key = RsaPublicKey::new(key.modulus.clone(), key.exponent.clone())
                .wrap_err("Constructing RSA public key failed")?;
            verify_signature_rsa::<D>(message, &public_key, sig)
        }
        // Error case for mismatched or unsupported combinations
        _ => bail!("Unsupported public key and signature combination"),
    }
}

fn verify_signature(
    message: &[u8],
    signature: &Signature,
    public_key: &Pubkey,
    digest_algo: &ObjectIdentifier,
) -> Result<()> {
    match *digest_algo {
        ID_SHA_224 => verify_signature_with_digest::<Sha224>(message, signature, public_key),
        ID_SHA_256 => verify_signature_with_digest::<Sha256>(message, signature, public_key),
        ID_SHA_384 => verify_signature_with_digest::<Sha384>(message, signature, public_key),
        ID_SHA_512 => verify_signature_with_digest::<Sha512>(message, signature, public_key),
        _ => bail!(
            "Unsupported digest algorithm: {} {:?}",
            digest_algo,
            DB.by_oid(digest_algo)
        ),
    }
}
//     let digest = digest(digest_algo, data)?;

//     match (public_key, signature) {
//         // P224
//         (Pubkey::EC(PubkeyEC::P224(coords)), Signature::EC(sig)) => {
//             use p224::ecdsa::{signature::Verifier, Signature as P224Signature};
//             let verifying_key = coords.to_verifying_key::<p224::NistP224>()?;
//             let sig_asn1 = Asn1Signature::try_from(sig)?;
//             let sig_der = sig_asn1.to_der()?;
//             let signature = P224Signature::from_der(&sig_der)?;
//             verifying_key
//                 .verify(&digest, &signature)
//                 .map_err(|e| eyre!("P224 ECDSA signature verification failed: {}", e))
//         }

//         // P256
//         (Pubkey::EC(PubkeyEC::P256(coords)), Signature::EC(sig)) => {
//             use p256::ecdsa::{signature::Verifier, Signature as P256Signature};
//             let verifying_key = coords.to_verifying_key::<p256::NistP256>()?;
//             let sig_asn1 = Asn1Signature::try_from(sig)?;
//             let sig_der = sig_asn1.to_der()?;
//             let signature = P256Signature::from_der(&sig_der)?;
//             verifying_key
//                 .verify(&digest, &signature)
//                 .map_err(|e| eyre!("P256 ECDSA signature verification failed: {}", e))
//         }

//         // P384
//         (Pubkey::EC(PubkeyEC::P384(coords)), Signature::EC(sig)) => {
//             use p384::ecdsa::{signature::Verifier, Signature as P384Signature};
//             let verifying_key = coords.to_verifying_key::<p384::NistP384>()?;
//             let sig_asn1 = Asn1Signature::try_from(sig)?;
//             let sig_der = sig_asn1.to_der()?;
//             let signature = P384Signature::from_der(&sig_der)?;
//             verifying_key
//                 .verify(&digest, &signature)
//                 .map_err(|e| eyre!("P384 ECDSA signature verification failed: {}", e))
//         }

//         // P521
//         (Pubkey::EC(PubkeyEC::P521(coords)), Signature::EC(sig)) => {
//             todo!();
//             // use p521::ecdsa::{signature::Verifier, Signature as P521Signature, VerifyingKey};
//             // let verifying_key = coords.to_verifying_key::<p521::NistP521>()?;
//             // let sig_asn1 = Asn1Signature::try_from(sig)?;
//             // let sig_der = sig_asn1.to_der()?;
//             // let signature = P521Signature::from_der(&sig_der)?;
//             // verifying_key
//             //     .verify_digest(digest.as_ref(), &signature)
//             //     .map_err(|e| eyre!("P521 ECDSA signature verification failed: {}", e))
//         }

//         // K256 (secp256k1)
//         (Pubkey::EC(PubkeyEC::K256(coords)), Signature::EC(sig)) => {
//             use k256::ecdsa::{signature::Verifier, Signature as K256Signature};
//             let verifying_key = coords.to_verifying_key::<k256::Secp256k1>()?;
//             let sig_asn1 = Asn1Signature::try_from(sig)?;
//             let sig_der = sig_asn1.to_der()?;
//             let signature = K256Signature::from_der(&sig_der)?;
//             verifying_key
//                 .verify(&digest, &signature)
//                 .map_err(|e| eyre!("K256 ECDSA signature verification failed: {}", e))
//         }

//         // RSA
//         (Pubkey::RSA(key), Signature::RSA(sig)) => {
//             use rsa::{Pkcs1v15Sign, RsaPublicKey};

//             let pub_key = RsaPublicKey::new(key.modulus.clone(), key.exponent.clone())?;

//             pub_key
//                 .verify(Pkcs1v15Sign::new_unprefixed(), &digest, sig.as_slice())
//                 .map_err(|e| eyre!("RSA signature verification failed: {}", e))
//         }

//         _ => bail!("Unsupported public key and signature combination"),
//     }
// }
