use color_eyre::Result;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use openssl::rsa::Rsa;
use openssl::x509::X509;

#[derive(Debug)]
pub enum OpenPubKey {
    EC {
        x: BigNum,
        y: BigNum,
        curve: Nid,
    },
    RSA {
        n: BigNum, // modulus
        e: BigNum, // public exponent
    },
}

impl OpenPubKey {
    pub fn algo_name(&self) -> Option<&'static str> {
        match self {
            OpenPubKey::EC { x, y, curve } => curve.short_name().map(|s| Some(s)).unwrap_or(None),
            OpenPubKey::RSA { n, e } => Some("rsa"),
        }
    }
}

pub fn parse_spki_params(spki_der: &[u8]) -> Result<OpenPubKey> {
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
            let curve = group.curve_name().unwrap_or(Nid::UNDEF);

            Ok(OpenPubKey::EC { x, y, curve })
        }
        Id::RSA => {
            let rsa = pkey.rsa()?;
            let n = rsa.n().to_owned()?;
            let e = rsa.e().to_owned()?;

            Ok(OpenPubKey::RSA { n, e })
        }
        _ => Err(color_eyre::eyre::eyre!("Unsupported key type")),
    }
}
