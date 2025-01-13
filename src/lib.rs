#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use color_eyre::eyre::{Result, WrapErr};
use emrtd_core::{bundle, document_components, master_certs};
use napi::bindgen_prelude::Buffer;
use once_cell::sync::Lazy;

const MASTERLIST_JSON: &str = include_str!("../assets/masterlist_284.json");
static MASTERLIST: Lazy<Vec<master_certs::MasterCert>> = Lazy::new(|| {
    serde_json::from_str(MASTERLIST_JSON).expect("Failed to parse masterlist JSON at compile time")
});

#[napi(object)]
pub struct PassportScan {
    pub sod: Buffer,
    pub dg1: Buffer,
}

#[napi]
pub fn create_bundle(scan: PassportScan) -> napi::Result<String> {
    (|| -> Result<String> {
        let sod = document_components::parse_sod(&scan.sod)?;
        let doc_comps = document_components::DocumentComponents::new(&sod, &scan.dg1)?;

        let masterlist = &*MASTERLIST;
        let bundle = bundle::VerificationBundle::bundle(&doc_comps, &masterlist)?;

        serde_json::to_string(&bundle).wrap_err("serializing bundle to json")
    })()
    .map_err(|e| napi::Error::from_reason(e.to_string()))
}
