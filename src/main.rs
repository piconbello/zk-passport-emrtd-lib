use clap::{Parser, Subcommand};
use color_eyre::eyre::{bail, Context, ContextCompat, Result};
use serde::Deserialize;
use serde_with::{base64::Base64, serde_as};
use std::fs;
use std::path::PathBuf;
use std::{fs::File, io::BufReader};
use zk_passport_emrtd_lib::{
    bundle, bundle_mock, bundle_verify::Verify, document_components, master_certs,
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// processes icaopkd-002-complete-000XXX.ldif file
    Masterlist {
        #[arg(required = true, value_name = "FILE")]
        ldif_file: PathBuf,
    },

    /// processes passportScan.json file
    Bundle {
        /// either ldif or masterlist.json
        #[arg(required = true, value_name = "FILE")]
        masterlist_file: PathBuf,

        /// json file with "sod" and "dg1" as base64
        #[arg(required = true, value_name = "FILE")]
        scan_file: PathBuf,
    },

    /// generates mock provable passport
    Mock {
        /// MRZ content of length 88
        #[arg(long)]
        mrz: Option<String>,
    },
}

fn parse_masterlist_from_ldif(ldif_file: &PathBuf) -> Result<Vec<master_certs::MasterCert>> {
    let f = File::open(ldif_file).wrap_err("opening ldif file")?;
    let reader = BufReader::new(f);
    let master_certs = master_certs::extract_master_certificates(reader)?;
    master_certs::distill_master_certificates(&master_certs)
}

pub fn handle_mock(mrz: Option<String>) -> Result<()> {
    let mrz: [u8; 88] = match mrz {
        None => *bundle_mock::MRZ_FRODO,
        Some(s) => {
            if s.len() != 88 || !s.is_ascii() {
                bail!("mrz must be 88 ASCII characters");
            }
            let mut arr = [0u8; 88];
            arr.copy_from_slice(s.as_bytes());
            arr
        }
    };
    let bundle = bundle_mock::mock_verification_bundle(&mrz)?;
    bundle.verify().wrap_err("verify mock bundle")?;
    println!("{}", serde_json::to_string_pretty(&bundle).unwrap());

    Ok(())
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct PassportScan {
    #[serde_as(as = "Base64")]
    pub sod: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub dg1: [u8; 93],
}

pub fn handle_bundle(masterlist_file: &PathBuf, scan_file: &PathBuf) -> Result<()> {
    let masterlist: Vec<master_certs::MasterCert> = match masterlist_file
        .extension()
        .wrap_err("masterlist file extension")?
        .to_str()
        .wrap_err("extension to str")?
    {
        "ldif" => parse_masterlist_from_ldif(masterlist_file),
        "json" => {
            let f = File::open(masterlist_file).wrap_err("opening masterlist json")?;
            let reader = BufReader::new(f);
            serde_json::from_reader(reader).wrap_err("parsing masterlist json")
        }
        _ => bail!("accepts .ldif or .json"),
    }?;

    let scan_text = fs::read_to_string(scan_file)?;
    let scan: PassportScan = serde_json::from_str(&scan_text)?;
    let sod = document_components::parse_sod(&scan.sod)?;

    let doc_comps = document_components::DocumentComponents::new(&sod, &scan.dg1)?;

    let bundle = bundle::VerificationBundle::bundle(&doc_comps, &masterlist)?;

    println!("{}", serde_json::to_string_pretty(&bundle)?);
    Ok(())
}

pub fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    match cli.command {
        Commands::Masterlist { ldif_file } => {
            let masterlist = parse_masterlist_from_ldif(&ldif_file)?;
            println!("{}", serde_json::to_string_pretty(&masterlist)?);
            Ok(())
        }
        Commands::Mock { mrz } => handle_mock(mrz),
        Commands::Bundle {
            masterlist_file,
            scan_file,
        } => handle_bundle(&masterlist_file, &scan_file),
    }
}
