use clap::{Parser, Subcommand};
use color_eyre::eyre::{Context, Result};
use sha2::Sha256;
use std::path::PathBuf;
use std::{fs::File, io::BufReader};
use zk_passport_emrtd_lib::mock::mock_passport_provable;

use zk_passport_emrtd_lib::parse_scan::{PassportProvable, PassportScan};

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

fn handle_scan(scan_file: &PathBuf) -> Result<()> {
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

fn handle_mock(mrz: Option<&str>) -> Result<()> {
    let provable = mock_passport_provable::<Sha256>(mrz)?;

    let json = serde_json::to_string_pretty(&provable)
        .wrap_err("serializing passport provable to json")?;

    println!("{}", json);

    Ok(())
}

fn main() -> Result<()> {
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
