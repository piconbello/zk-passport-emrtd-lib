use crate::{
    bundle::{Asn1Signature, Signature, VerificationBundle},
    pubkeys::Pubkey,
};
use color_eyre::eyre::{bail, eyre, Context, Result};
use const_oid::{
    db::rfc5912::{ID_SHA_224, ID_SHA_256, ID_SHA_384, ID_SHA_512},
    ObjectIdentifier,
};
use der::Encode;
use openssl::{
    hash::{Hasher, MessageDigest},
    pkey::{PKey, Public},
    sign::Verifier,
};

pub trait Verify {
    fn verify(&self) -> Result<()>;
}

impl Verify for VerificationBundle {
    fn verify(&self) -> Result<()> {
        // 1. Verify that digest of dg1 is in lds
        let dg1_digest = compute_digest(&self.dg1, &self.digest_algo)?;
        if !self
            .lds
            .windows(dg1_digest.len())
            .any(|window| window == dg1_digest)
        {
            return Err(eyre!("DG1 digest not found in LDS"));
        }

        // 2. Verify that digest of lds is in signed_attrs
        let lds_digest = compute_digest(&self.lds, &self.digest_algo)?;
        if !self
            .signed_attrs
            .windows(lds_digest.len())
            .any(|window| window == lds_digest)
        {
            return Err(eyre!("LDS digest not found in signed attributes"));
        }

        // 3. Verify that signed_attrs is signed by the local cert
        let ds_pkey = match &self.cert_local_pubkey {
            Pubkey::EC(ec) => {
                let group = openssl::ec::EcGroup::from_curve_name(ec.curve)?;
                let mut ctx = openssl::bn::BigNumContext::new()?;
                let mut point = openssl::ec::EcPoint::new(&group)?;
                point.set_affine_coordinates_gfp(&group, &ec.x, &ec.y, &mut ctx)?;
                let ec_key = openssl::ec::EcKey::from_public_key(&group, &point)?;
                PKey::from_ec_key(ec_key)?
            }
            Pubkey::RSA(_rsa) => {
                todo!();
            }
        };

        verify_signature(
            &self.signed_attrs,
            &self.document_signature,
            &ds_pkey,
            &self.cert_local_tbs_digest_algo,
        )
        .wrap_err("verifying document")?;

        // 4. Verify that local cert is signed by the master cert
        let master_pkey = match &self.cert_master_pubkey {
            Pubkey::EC(ec) => {
                let group = openssl::ec::EcGroup::from_curve_name(ec.curve)?;
                let mut ctx = openssl::bn::BigNumContext::new()?;
                let mut point = openssl::ec::EcPoint::new(&group)?;
                point.set_affine_coordinates_gfp(&group, &ec.x, &ec.y, &mut ctx)?;
                let ec_key = openssl::ec::EcKey::from_public_key(&group, &point)?;
                PKey::from_ec_key(ec_key)?
            }
            Pubkey::RSA(_rsa) => {
                todo!();
            }
        };

        verify_signature(
            &self.cert_local_tbs,
            &self.cert_local_signature,
            &master_pkey,
            &self.cert_local_tbs_digest_algo,
        )
        .wrap_err("verifying cert")?;

        Ok(())
    }
}

fn message_digest(algo: &ObjectIdentifier) -> Result<MessageDigest> {
    match *algo {
        ID_SHA_224 => Ok(MessageDigest::sha224()),
        ID_SHA_256 => Ok(MessageDigest::sha256()),
        ID_SHA_384 => Ok(MessageDigest::sha384()),
        ID_SHA_512 => Ok(MessageDigest::sha512()),
        _ => Err(eyre!("Unsupported digest algorithm")),
    }
}

fn compute_digest(data: &[u8], algo: &ObjectIdentifier) -> Result<Vec<u8>> {
    let md = message_digest(algo)?;
    let mut hasher = Hasher::new(md)?;
    hasher.update(data)?;
    Ok(hasher.finish()?.to_vec())
}

fn verify_signature(
    data: &[u8],
    signature: &Signature,
    public_key: &PKey<Public>,
    digest_algo: &ObjectIdentifier,
) -> Result<()> {
    let md = message_digest(digest_algo)?;
    let mut verifier = Verifier::new(md, public_key)?;
    verifier.update(data)?;

    // Convert EC signatures to ASN.1 DER format for OpenSSL verification
    let signature_bytes = match signature {
        Signature::EC(ec_sig) => {
            let asn1_sig = Asn1Signature::try_from(ec_sig)?;
            asn1_sig.to_der()?
        }
        Signature::RSA(rsa_sig) => rsa_sig.to_vec(),
    };

    // Verify the signature and convert OpenSSL result into our Result type
    match verifier.verify(&signature_bytes) {
        Ok(true) => Ok(()),
        Ok(false) => bail!("Invalid signature"),
        Err(e) => bail!("Verification error: {}", e),
    }
}
