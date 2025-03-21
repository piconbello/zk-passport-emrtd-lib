use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use color_eyre::eyre::{Context, Result};
use emrtd_core::{bundle as core_bundle, dg1::DG1Variant, document_components, smallvec::SmallVec};
use serde::de::{self, Error as DeError, Visitor};
use serde::{Deserialize, Deserializer};
use std::path::PathBuf;
use std::{fmt, fs};

use crate::masterlist;

#[derive(Debug)]
pub struct PassportScan {
    pub sod: Vec<u8>,
    pub dg1: SmallVec<[u8; 128]>,
    pub dg1_variant: DG1Variant,
}

impl<'de> Deserialize<'de> for PassportScan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PassportScanVisitor;

        impl<'de> Visitor<'de> for PassportScanVisitor {
            type Value = PassportScan;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON object with scannedDataGroupList")
            }

            fn visit_map<V>(self, mut map: V) -> Result<PassportScan, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut dg1_base64 = None;
                let mut sod_base64 = None;

                while let Some(key) = map.next_key::<String>()? {
                    if key == "scannedDataGroupList" {
                        let data_groups: Vec<Vec<String>> = map.next_value()?;
                        for group in data_groups {
                            if group.len() != 2 {
                                return Err(DeError::custom(
                                    "Each data group must have exactly 2 elements",
                                ));
                            }

                            match group[0].as_str() {
                                "DG1" => dg1_base64 = Some(group[1].clone()),
                                "SOD" => sod_base64 = Some(group[1].clone()),
                                _ => {}
                            }
                        }
                        // break;
                    } else {
                        // Important: Consume the value even if we don't use the key.
                        let _: serde_json::Value = map.next_value()?;
                    }
                }

                let dg1_base64 = dg1_base64.ok_or_else(|| DeError::missing_field("DG1"))?;
                let sod_base64 = sod_base64.ok_or_else(|| DeError::missing_field("SOD"))?;

                // Decode base64
                let sod = BASE64_STANDARD
                    .decode(&sod_base64)
                    .map_err(|e| DeError::custom(format!("Failed to decode SOD: {}", e)))?;

                let dg1_vec = BASE64_STANDARD
                    .decode(&dg1_base64)
                    .map_err(|e| DeError::custom(format!("Failed to decode DG1: {}", e)))?;

                let dg1 = SmallVec::from_vec(dg1_vec);

                // Parse DG1Variant
                let dg1_variant = DG1Variant::try_from(dg1.as_slice())
                    .map_err(|e| DeError::custom(format!("Failed to parse DG1 variant: {}", e)))?;

                Ok(PassportScan {
                    sod,
                    dg1,
                    dg1_variant,
                })
            }
        }

        deserializer.deserialize_map(PassportScanVisitor)
    }
}

pub fn handle_bundle(masterlist_json_file: &PathBuf, scan_file: &PathBuf) -> Result<()> {
    let masterlist = masterlist::parse_masterlist_from_json(masterlist_json_file).wrap_err("")?;
    let scan_text = fs::read_to_string(scan_file)?;

    // Parse the JSON directly into PassportScan
    // eprintln!("{}", &scan_text);
    let scan: PassportScan = serde_json::from_str(&scan_text)?;
    // eprintln!("{:?}", &scan);

    let sod = document_components::parse_sod(&scan.sod)?;
    let doc_comps =
        document_components::DocumentComponents::new(&sod, &scan.dg1, scan.dg1_variant)?;

    let bundle = core_bundle::VerificationBundle::bundle(&doc_comps, masterlist.pairs.as_slice())?;

    println!("{}", serde_json::to_string_pretty(&bundle)?);
    Ok(())
}
