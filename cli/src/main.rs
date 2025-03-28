use clap::{Parser, Subcommand};
use color_eyre::eyre::{bail, Result};
use emrtd_core::rsa_message_template::RsaMessageTemplates;
use emrtd_core::{
    bundle::VerificationBundle, bundle_verify::Verify, dg1::DG1Variant, smallvec::SmallVec,
};
use serde::Deserialize;
use serde_with::{base64::Base64, serde_as};
use std::fs;
use std::path::PathBuf;

mod bundle;
mod masterlist;
mod mock_alt;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// processes icaopkd-002-complete-000XXX.ldif file or a .pem file
    GenerateMasterlist {
        #[arg(required = true, value_name = "LDIF_OR_PEM_FILE")]
        input_file: PathBuf,
    },

    /// processes passportScan.json file
    Bundle {
        /// json file with "sod" and "dg1" as base64
        #[arg(required = true, value_name = "SCAN_FILE")]
        scan_file: PathBuf,

        /// either ldif or masterlist.json
        #[arg(required = true, value_name = "MASTERLIST_JSON_FILE")]
        masterlist_json_file: PathBuf,
    },

    /// generates mock provable passport
    Mock {
        #[arg(required = true, value_name = "CONFIG_FILE")]
        config: PathBuf,
    },

    /// verifies a bundle file
    Verify {
        #[arg(required = true, value_name = "BUNDLE_FILE")]
        bundle_file: PathBuf,
    },

    /// generates rsa message templates json
    RsaMessageTemplate {},
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct PassportScan {
    #[serde_as(as = "Base64")]
    pub sod: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub dg1: SmallVec<[u8; 128]>,
    pub dg1_variant: DG1Variant,
}

pub fn handle_verify(bundle_file: &PathBuf) -> Result<()> {
    let bundle_text = fs::read_to_string(bundle_file)?;
    let bundle: VerificationBundle = serde_json::from_str(&bundle_text)?;

    match bundle.verify() {
        Ok(()) => {
            println!("Bundle verification successful!");
            Ok(())
        }
        Err(e) => {
            bail!("Bundle verification failed: {}", e);
        }
    }
}

pub fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateMasterlist { input_file } => {
            masterlist::handle_generate_masterlist(&input_file)
        }
        Commands::Mock { config } => mock_alt::handle_mock(&config),
        Commands::Bundle {
            masterlist_json_file,
            scan_file,
        } => bundle::handle_bundle(&masterlist_json_file, &scan_file),
        Commands::Verify { bundle_file } => handle_verify(&bundle_file),
        Commands::RsaMessageTemplate {} => {
            let templates = RsaMessageTemplates::generate();
            let s = serde_json::to_string_pretty(&templates).expect("");
            println!("{}", &s);
            Ok(())
        }
    }
}
