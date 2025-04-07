use crate::{bundle::VerificationBundle, bundle_signature::Signature, pubkeys::Pubkey};
use color_eyre::eyre::{bail, eyre, Context, Result};
use openssl::{
    hash::{Hasher, MessageDigest},
    nid::Nid,
    pkey::{PKey, Public},
    sign::Verifier,
};

pub trait Verify {
    fn verify(&self) -> Result<()>;
}

impl VerificationBundle {
    fn verify_head(&self) -> Result<()> {
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
        Ok(())
    }
    fn verify_tail_ec(&self) -> Result<()> {
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
                bail!("Master pubkey is RSA, in verify_tail_ec");
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

    fn verify_tail_rsa(&self) -> Result<()> {
        // Get local cert public key
        let ds_pkey = match &self.cert_local_pubkey {
            Pubkey::RSA(rsa) => {
                let rsa_key = openssl::rsa::Rsa::from_public_components(
                    rsa.modulus.as_ref().to_owned()?,
                    rsa.exponent.as_ref().to_owned()?,
                )?;
                PKey::from_rsa(rsa_key)?
            }
            _ => bail!("Expected RSA key for RSA verification"),
        };

        verify_signature(
            &self.signed_attrs,
            &self.document_signature,
            &ds_pkey,
            &self.cert_local_tbs_digest_algo,
        )
        .wrap_err("verifying RSA document")?;

        // Get master cert public key
        let master_pkey = match &self.cert_master_pubkey {
            Pubkey::RSA(rsa) => {
                let rsa_key = openssl::rsa::Rsa::from_public_components(
                    rsa.modulus.as_ref().to_owned()?,
                    rsa.exponent.as_ref().to_owned()?,
                )?;
                PKey::from_rsa(rsa_key)?
            }
            _ => bail!("Expected RSA key for RSA verification"),
        };

        verify_signature(
            &self.cert_local_tbs,
            &self.cert_local_signature,
            &master_pkey,
            &self.cert_local_tbs_digest_algo,
        )
        .wrap_err("verifying RSA cert")?;

        Ok(())
    }
}

impl Verify for VerificationBundle {
    fn verify(&self) -> Result<()> {
        self.verify_head()?;

        match &self.cert_local_pubkey {
            Pubkey::EC(_) => self.verify_tail_ec()?,
            Pubkey::RSA(_) => self.verify_tail_rsa()?,
        }
        Ok(())
    }
}

fn message_digest(algo: &Nid) -> Result<MessageDigest> {
    match *algo {
        Nid::SHA224 => Ok(MessageDigest::sha224()),
        Nid::SHA256 => Ok(MessageDigest::sha256()),
        Nid::SHA384 => Ok(MessageDigest::sha384()),
        Nid::SHA512 => Ok(MessageDigest::sha512()),
        _ => Err(eyre!("Unsupported digest algorithm")),
    }
}

fn compute_digest(data: &[u8], algo: &Nid) -> Result<Vec<u8>> {
    let md = message_digest(algo)?;
    let mut hasher = Hasher::new(md)?;
    hasher.update(data)?;
    Ok(hasher.finish()?.to_vec())
}

fn verify_signature(
    data: &[u8],
    signature: &Signature,
    public_key: &PKey<Public>,
    digest_algo: &Nid,
) -> Result<()> {
    let md = message_digest(digest_algo)?;
    let mut verifier = Verifier::new(md, public_key)?;
    verifier.update(data)?;

    // Convert EC signatures to ASN.1 DER format for OpenSSL verification
    let signature_bytes = match signature {
        Signature::Ec(ec_sig) => {
            ec_sig.uncompressed.clone()
            // let asn1_sig = Asn1Signature::try_from(ec_sig)?;
            // asn1_sig.to_der()?
        }
        Signature::RsaPss(rsa_sig) => rsa_sig.signature.to_vec(),
        Signature::RsaPkcs(rsa_sig) => rsa_sig.signature.to_vec(),
    };

    // Verify the signature and convert OpenSSL result into our Result type
    match verifier.verify(&signature_bytes) {
        Ok(true) => Ok(()),
        Ok(false) => bail!("Invalid signature"),
        Err(e) => bail!("Verification error: {}", e),
    }
}
