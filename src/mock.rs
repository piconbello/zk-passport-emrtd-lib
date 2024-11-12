use std::collections::BTreeSet;

use color_eyre::eyre::{bail, Result};
use const_oid::AssociatedOid;
use der::{asn1::OctetString, Encode};
use digest::{Digest, OutputSizeUser};

use crate::{
    dg1::{Dg1Td3, MrzTd3, MRZ_TD3_HEADER},
    lds::{DatagroupDigest, DigestAlgorithm, LDSSecurityObject},
    parse_scan::PassportProvable,
    signed_attrs::prepare_signed_attributes,
};

const MRZ_FRODO: &MrzTd3 =
    b"P<GBRBAGGINS<<FRODO<<<<<<<<<<<<<<<<<<<<<<<<<P231458901GBR6709224M2209151ZE184226B<<<<<18";

pub fn mock_dg1(mrz: Option<&str>) -> Result<Dg1Td3> {
    let mut dg1: Dg1Td3 = [0u8; 93];
    dg1[..5].copy_from_slice(&MRZ_TD3_HEADER);

    match mrz {
        None => {
            dg1[5..].copy_from_slice(MRZ_FRODO);
        }
        Some(s) => {
            if !s.is_ascii() {
                bail!("MRZ must contain only ASCII characters");
            }

            let bytes = s.as_bytes();
            if bytes.len() != 88 {
                bail!("MRZ must be exactly 88 characters long");
            }

            dg1[5..].copy_from_slice(bytes);
        }
    };

    Ok(dg1)
}

fn hash_serialize_datagroup<H: Digest>(
    n: u8,
    datagroup_content: impl AsRef<[u8]>,
) -> DatagroupDigest {
    let digest = H::digest(datagroup_content).to_vec();
    let hash_serialized = OctetString::new(digest).expect("digest serializes as octet string");
    DatagroupDigest {
        datagroup_number: n,
        digest: hash_serialized,
    }
}

pub fn mock_lds<H: Digest + OutputSizeUser + AssociatedOid>(
    dg1: &Dg1Td3,
    include_dgs: BTreeSet<u8>,
) -> Vec<u8> {
    let mut dg_hashes = Vec::new();
    dg_hashes.push(hash_serialize_datagroup::<H>(1, dg1));
    include_dgs
        .into_iter()
        .filter(|n| *n != 1u8)
        .for_each(|n| dg_hashes.push(hash_serialize_datagroup::<H>(n, [n])));

    let lds = LDSSecurityObject {
        version: 0,
        digest_algorithm: DigestAlgorithm { algorithm: H::OID },
        dg_digests: dg_hashes,
    };

    lds.to_der().expect("infallible")
}

pub fn mock_passport_provable<H: Digest + OutputSizeUser + AssociatedOid>(
    mrz: Option<&str>,
) -> Result<PassportProvable> {
    let dg1 = mock_dg1(mrz)?;
    let lds = mock_lds::<H>(&dg1, BTreeSet::from([1, 2, 3, 11, 12, 14]));
    let lds_digest = H::digest(&lds);
    let signed_attrs_asn1 = prepare_signed_attributes(&lds_digest);
    let signed_attrs = signed_attrs_asn1.to_der().expect("infallible");
    Ok(PassportProvable {
        dg1,
        lds,
        signed_attrs,
    })
}
