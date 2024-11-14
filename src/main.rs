use clap::{Parser, Subcommand};
use color_eyre::eyre::{Context, ContextCompat, Result};
use const_oid::db::DB;
use sha2::Sha256;
use std::path::PathBuf;
use std::{fs::File, io::BufReader};
use zk_passport_emrtd_lib::cert_local::extract_passport_verification_input;
use zk_passport_emrtd_lib::mock::mock_passport_provable;

use zk_passport_emrtd_lib::parse_scan::{
    extract_certificate, extract_signer_info, parse_sod, PassportProvable, PassportScan,
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// processes passportScan.json file
    Scan {
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

pub fn handle_scan(scan_file: &PathBuf) -> Result<()> {
    let f = File::open(scan_file).wrap_err("opening passport scan")?;
    let reader = BufReader::new(f);
    let scan: PassportScan =
        serde_json::from_reader(reader).wrap_err("parsing passport scan json")?;

    let provable = PassportProvable::try_from(&scan)?;

    let json = serde_json::to_string_pretty(&provable)
        .wrap_err("serializing passport provable to json")?;

    println!("{}", json);

    Ok(())
}

pub fn handle_mock(mrz: Option<&str>) -> Result<()> {
    let provable = mock_passport_provable::<Sha256>(mrz)?;

    let json = serde_json::to_string_pretty(&provable)
        .wrap_err("serializing passport provable to json")?;

    println!("{}", json);

    Ok(())
}

pub fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { scan_file } => {
            handle_scan(scan_file)?;
        }
        Commands::Mock { mrz } => {
            handle_mock(mrz.as_deref())?;
        }
    }

    Ok(())
}

pub fn main2() -> Result<()> {
    color_eyre::install()?;
    let f = File::open("./passportScan.json").wrap_err("opening passport scan")?;
    let reader = BufReader::new(f);
    let scan: PassportScan =
        serde_json::from_reader(reader).wrap_err("parsing passport scan json")?;

    let sod = parse_sod(&scan.sod)?;

    let signer_info = extract_signer_info(&sod)?;
    let cert = extract_certificate(&sod)?;

    let verification_input = extract_passport_verification_input(signer_info, cert)?;
    // *verification_input.signed_attrs.last_mut().unwrap() -= 1;
    verification_input.verify()?;
    let pubkey = verification_input.curve_ops.public_key_coords();
    let signature = verification_input.curve_ops.signature_components();
    println!("{}", serde_json::to_string_pretty(&pubkey).unwrap());
    println!("{}", serde_json::to_string_pretty(&signature).unwrap());
    println!("hash algo {}", verification_input.hasher.algo_name());
    println!("sign algo {}", verification_input.curve_ops.algo_name());

    Ok(())
}
