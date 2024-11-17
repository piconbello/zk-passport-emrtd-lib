use color_eyre::eyre::{bail, Context, ContextCompat, Error};
use der::{asn1::BitString, Any, Encode};
use openssl::{
    bn::{BigNum, BigNumContext},
    nid::Nid,
    pkey::{Id, PKey},
};
use spki::SubjectPublicKeyInfo;

pub enum Pubkey {
    EC(PubkeyEC),
    RSA(PubkeyRSA),
}

pub struct PubkeyEC {
    pub curve: Nid,
    pub x: BigNum,
    pub y: BigNum,
}

pub struct PubkeyRSA {
    pub modulus: BigNum,
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
