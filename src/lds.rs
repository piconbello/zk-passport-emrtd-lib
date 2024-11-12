use color_eyre::{
    eyre::{eyre, Context},
    Result,
};
use std::collections::BTreeMap;

use der::{asn1::OctetString, Sequence, ValueOrd};
use digest::{
    const_oid::{AssociatedOid, ObjectIdentifier},
    Digest, OutputSizeUser,
};
#[derive(Sequence, Debug)]
pub struct LDSSecurityObject {
    pub version: i32,
    pub digest_algorithm: DigestAlgorithm,
    pub dg_digests: Vec<DatagroupDigest>,
}

#[derive(Sequence, Debug)]
pub struct DigestAlgorithm {
    pub algorithm: ObjectIdentifier,
}

#[derive(Sequence, Debug, ValueOrd)]
pub struct DatagroupDigest {
    pub datagroup_number: u8,
    pub digest: OctetString,
}

pub fn prepare_lds<H: Digest + OutputSizeUser + AssociatedOid>(
    dgs_digests: &BTreeMap<u8, &[u8]>,
) -> Result<LDSSecurityObject> {
    let dgs: Result<Vec<DatagroupDigest>> = dgs_digests
        .iter()
        .map(|(n, d)| {
            if d.len() != <H as OutputSizeUser>::output_size() {
                Err(eyre!("wrong sized digest"))
            } else {
                let oc =
                    OctetString::new(d.to_vec()).wrap_err("can build octetstring from digest")?;
                Ok(DatagroupDigest {
                    datagroup_number: *n,
                    digest: oc,
                })
            }
        })
        .collect();
    let dgs = dgs.wrap_err("serializing dg digests")?;

    Ok(LDSSecurityObject {
        version: 0,
        digest_algorithm: DigestAlgorithm { algorithm: H::OID },
        dg_digests: dgs,
    })
}
