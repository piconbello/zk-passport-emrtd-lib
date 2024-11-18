use clap::{Parser, Subcommand};
use color_eyre::eyre::{Context, Result};
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs::File, io::BufReader};
use zk_passport_emrtd_lib::bundle::VerificationBundle;
use zk_passport_emrtd_lib::cert_local::{
    extract_cert_local_verification_input, extract_cert_master_verification_input,
};
use zk_passport_emrtd_lib::document_components::DocumentComponents;
use zk_passport_emrtd_lib::mock::mock_passport_provable;
use zk_passport_emrtd_lib::parse_ldif::{
    certificates_from_ldif, extract_subject_identifier_key, MasterCert, MasterCertPubkey,
};
use zk_passport_emrtd_lib::{master_certs, mock_bundle};

use zk_passport_emrtd_lib::bundle_verify::Verify;
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

pub fn main1() -> Result<()> {
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
    let f = File::open("./passportScan.egemen.json").wrap_err("opening passport scan")?;
    let reader = BufReader::new(f);
    let scan: PassportScan =
        serde_json::from_reader(reader).wrap_err("parsing passport scan json")?;

    let sod = parse_sod(&scan.sod)?;

    let signer_info = extract_signer_info(&sod)?;
    let cert = extract_certificate(&sod)?;

    let verification_input = extract_cert_local_verification_input(signer_info, cert)?;
    // *verification_input.signed_attrs.last_mut().unwrap() -= 1;
    verification_input.verify()?;
    let pubkey = verification_input.curve_ops.public_key_coords();
    let signature = verification_input.curve_ops.signature_components();
    println!("{}", serde_json::to_string_pretty(&pubkey).unwrap());
    println!("{}", serde_json::to_string_pretty(&signature).unwrap());
    println!("hash algo {}", verification_input.hasher.algo_name());
    println!("sign algo {}", verification_input.curve_ops.algo_name());

    let master_certs =
        certificates_from_ldif(&PathBuf::from_str("icaopkd-002-complete-000284.ldif")?)?;

    println!("\nNOW master cert:");

    let verification_input_master_cert =
        extract_cert_master_verification_input(cert, &master_certs)?;
    verification_input_master_cert.verify()?;
    let pubkey = verification_input_master_cert.curve_ops.public_key_coords();
    let signature = verification_input_master_cert
        .curve_ops
        .signature_components();
    println!("{}", serde_json::to_string_pretty(&pubkey).unwrap());
    println!("{}", serde_json::to_string_pretty(&signature).unwrap());
    println!(
        "hash algo {}",
        verification_input_master_cert.hasher.algo_name()
    );
    println!(
        "sign algo {}",
        verification_input_master_cert.curve_ops.algo_name()
    );

    Ok(())
}

pub fn main3() -> Result<(), Box<dyn std::error::Error>> {
    use cms::cert::x509::Certificate;
    use color_eyre::eyre::eyre;
    use der::Decode;
    use std::fs;

    // Read the PEM file
    let pem_content = fs::read_to_string("icaopkd-002-complete-000284.pem")?;

    let pems = pem::parse_many(pem_content.as_bytes())?;

    let certs: Result<Vec<Certificate>> = pems
        .into_iter()
        .map(|p| match p.tag() {
            "CERTIFICATE" => Certificate::from_der(p.contents()).wrap_err("certificate from der"),
            tag => Err(eyre!("unaccepted tag {}", tag)),
        })
        .collect();

    let certs = certs?;

    certs.iter().for_each(|c| {
        let tbs = &c.tbs_certificate;

        println!("Subject: {:?}", tbs.subject);
        println!("Issuer: {:?}", tbs.issuer);
        println!("Validity:");
        println!("  Not Before: {:?}", tbs.validity.not_before);
        println!("  Not After: {:?}", tbs.validity.not_after);
        println!("Serial Number: {:?}", tbs.serial_number);

        // Print extensions if present
        if let Some(extensions) = &tbs.extensions {
            println!("Extensions:");
            for ext in extensions.iter() {
                println!("  ID: {:?}", ext.extn_id);
            }
        }

        println!("----------------------------------------");
    });

    Ok(())
}

// pub fn main4() -> Result<()> {
//     let master_certs =
//         certificates_from_ldif(&PathBuf::from_str("icaopkd-002-complete-000284.ldif")?)?;

//     let country_algo_pairs: Result<Vec<_>> = master_certs
//         .iter()
//         .map(|cert| {
//             let country = cert
//                 .tbs_certificate
//                 .subject
//                 .0
//                 .iter()
//                 .find_map(|dist| dist.0.get(0))
//                 .filter(|atv| atv.oid == COUNTRY_NAME)
//                 .and_then(|atv| PrintableStringRef::try_from(&atv.value).ok())
//                 .map(|s| s.to_string());
//             let spki_der = cert
//                 .tbs_certificate
//                 .subject_public_key_info
//                 .to_der()
//                 .unwrap();
//             let opk = parse_spki_params(&spki_der)?;
//             let algo_name = opk.algo_name().wrap_err("algo_name error")?;

//             Ok((country, algo_name))
//         })
//         .collect();

//     let certs_per_country: HashMap<Option<String>, HashSet<String>> = country_algo_pairs?
//         .into_iter()
//         .fold(HashMap::new(), |mut map, (country, algo)| {
//             map.entry(country)
//                 .or_insert_with(HashSet::new)
//                 .insert(algo.to_owned());
//             map
//         });

//     let printable_map: BTreeMap<String, HashSet<String>> = certs_per_country
//         .into_iter()
//         .map(|(country, algos)| (country.unwrap_or_else(|| "unknown".to_string()), algos))
//         .collect();

//     println!("{}", serde_json::to_string_pretty(&printable_map).unwrap());

//     Ok(())
// }

pub fn main6() -> Result<()> {
    let master_certs =
        certificates_from_ldif(&PathBuf::from_str("icaopkd-002-complete-000284.ldif")?)?;

    let parsed: Result<Vec<_>> = master_certs
        .into_iter()
        .map(|cert| {
            let subject_key_id = extract_subject_identifier_key(&cert)?;
            let pubkey = MasterCertPubkey::try_from(&cert.tbs_certificate.subject_public_key_info)?;
            Ok(MasterCert {
                pubkey,
                subject_key_id,
            })
        })
        .collect();

    let mut parsed = parsed?;
    parsed.sort_unstable_by(|a, b| a.subject_key_id.cmp(&b.subject_key_id));

    println!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    Ok(())
}

pub fn main() -> Result<()> {
    color_eyre::install()?;
    let f = File::open("icaopkd-002-complete-000284.ldif").wrap_err("opening ldif file")?;
    let reader = BufReader::new(f);
    let master_certs = master_certs::extract_master_certificates(reader)?;
    let distilled = master_certs::distill_master_certificates(&master_certs)?;

    let scan_text = fs::read_to_string("passportScan.egemen.json")?;
    let scan: PassportScan = serde_json::from_str(&scan_text)?;
    let sod = parse_sod(&scan.sod)?;

    let components = DocumentComponents::new(&sod, &scan.dg1)?;

    let bundle = VerificationBundle::bundle(&components, &distilled)?;

    println!("{}", serde_json::to_string_pretty(&bundle).unwrap());

    bundle.verify().wrap_err("verify bundle")?;

    let mocked_bundle = mock_bundle::mock_verification_bundle(mock_bundle::MRZ_FRODO)?;

    println!("{}", serde_json::to_string_pretty(&mocked_bundle).unwrap());

    mocked_bundle.verify().wrap_err("verify mock bundle")?;

    Ok(())
}
