use std::fs;
use std::io::Write;
use std::path::Path;

use super::format::PemItem;
use super::Signed;
use color_eyre::eyre::{self, Context};
use color_eyre::Help;
use itertools::Itertools;
use tracing::{instrument, warn};

use crate::config::{Encoding, Output, OutputConfig};
use crate::Config;

#[instrument(level = "debug", skip(certificate))]
fn write_signed(
    encoding: Encoding,
    certificate: impl PemItem,
    operation: Operation,
) -> eyre::Result<()> {
    let bytes = match encoding {
        Encoding::PEM => certificate.as_bytes(),
        Encoding::DER => certificate.der().into_bytes(),
    };
    match operation {
        Operation::Append(path) => {
            let mut file = fs::OpenOptions::new().append(true).open(path)?;
            file.write_all(&bytes)
                .wrap_err("Could not append signed certificate to pem file")
        }
        Operation::Create(path) => {
            let mut file = fs::File::create(path)?;
            file.write_all(&bytes)
                .wrap_err("could not create signed certificate file")
        }
    }
}

#[instrument(level = "debug", skip(private_key))]
fn write_key(
    encoding: Encoding,
    private_key: impl PemItem,
    operation: Operation,
) -> eyre::Result<()> {
    let bytes = match encoding {
        Encoding::PEM => private_key.as_bytes(),
        Encoding::DER => private_key.der().into_bytes(),
    };

    match operation {
        Operation::Append(path) => {
            let mut file = fs::OpenOptions::new().append(true).open(path)?;
            file.write_all(&bytes)
                .wrap_err("Could not append private key to pem file")
        }
        Operation::Create(path) => {
            let mut file = fs::File::create(path)
                .wrap_err("could not create private key file")
                .with_note(|| format!("path: {path:?}"))?;
            file.write_all(&bytes)
                .wrap_err("could not write to private key file")
                .with_note(|| format!("path: {path:?}"))
        }
    }
}

fn write_chain<P: PemItem>(
    encoding: Encoding,
    chain: Vec<P>,
    operation: Operation,
) -> eyre::Result<()> {
    if encoding == Encoding::DER {
        let Operation::Create(path) = operation else {
            unreachable!("appending to der files makes no sense")
        };
        for (i, cert) in chain.into_iter().enumerate() {
            let bytes = cert.der().into_bytes();
            let path = path.with_file_name(format!("{i}_chain.der"));

            let mut file = fs::File::create(path)?;
            file.write_all(&bytes)
                .wrap_err("could not create certificate chain file")?;
        }
        return Ok(());
    }

    let bytes: Vec<u8> = Itertools::intersperse(
        chain.iter().map(P::as_bytes),
        "\n".as_bytes().to_vec(),
    )
    .flatten()
    .collect();

    match operation {
        Operation::Append(path) => {
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(path)
                .wrap_err("could not append to chain file")
                .with_note(|| format!("path: {path:?}"))?;
            file.write_all(&bytes)
                .wrap_err("could not write to chain file")
        }
        Operation::Create(path) => {
            let mut file = fs::File::create(path)
                .wrap_err("could not create chain file")
                .with_note(|| format!("path: {path:?}"))?;
            file.write_all(&bytes)
                .wrap_err("could not create certificate chain file")
        }
    }
}

#[derive(Debug)]
enum Operation<'a> {
    Append(&'a Path),
    Create(&'a Path),
}

#[instrument(level = "debug", skip(config, signed, stdout), ret)]
pub fn on_disk<P: PemItem>(
    config: &Config,
    signed: Signed<P>,
    stdout: &mut impl Write,
) -> eyre::Result<()> {
    use Operation::{Append, Create};
    let OutputConfig {
        output,
        cert_path,
        key_path,
        chain_path,
    } = &config.output_config;

    let encoding = Encoding::from(output);
    let Signed {
        certificate,
        private_key,
        chain,
    } = signed;

    let chain_len = chain.len();
    match config.output_config.output {
        Output::PemSingleFile => {
            write_signed(encoding, certificate, Create(cert_path.as_path()))?;
            write_chain(encoding, chain, Append(cert_path.as_path()))?;
            write_key(encoding, private_key, Append(cert_path.as_path()))?;
        }
        Output::PemSeperateKey => {
            write_signed(encoding, certificate, Create(cert_path.as_path()))?;
            write_chain(encoding, chain, Append(cert_path.as_path()))?;
            write_key(encoding, private_key, Create(key_path.as_path()))?;
        }
        Output::PemSeperateChain => {
            write_chain(encoding, chain, Create(chain_path.as_path()))?;
            write_signed(encoding, certificate, Create(cert_path.as_path()))?;
            write_key(encoding, private_key, Append(cert_path.as_path()))?;
        }
        Output::PemAllSeperate | Output::Der => {
            write_chain(encoding, chain, Create(chain_path.as_path()))?;
            write_signed(encoding, certificate, Create(cert_path.as_path()))?;
            write_key(encoding, private_key, Create(key_path.as_path()))?;
        }
    }

    print_status(stdout, &config.output_config, chain_len);

    Ok(())
}

fn print_status(stdout: &mut impl Write, config: &OutputConfig, chain_len: usize) {
    let OutputConfig {
        output,
        cert_path,
        key_path,
        chain_path,
    } = config;

    let der_chain_files: String = (0..chain_len)
        .into_iter()
        .map(|i| format!("\t- {i}_chain.der\n"))
        .collect();
    let n_der_files = 2 + chain_len;

    match output {
        Output::PemSingleFile => writeln!(
            stdout,
            "created a single pem file:
    - {cert_path} 
    containing in order from top to bottom:
        - signed certificate
        - certificate chain
        - private key"
        ),
        Output::PemSeperateKey => writeln!(
            stdout,
            "created two pem files:
    - {cert_path}, 
    containing in order from top to bottom:
        - signed certificate
        - certificate chain
    - {key_path}
    containing the signed certificates private key"
        ),
        Output::PemSeperateChain => writeln!(
            stdout,
            "created two pem files:
    - {cert_path}, 
    containing in order from top to bottom:
        - signed certificate
        - its private key
    - {chain_path}
    containing the certificate chain"
        ),
        Output::PemAllSeperate => writeln!(
            stdout,
            "created three pem files:
    - {cert_path}, 
    containing the signed certificate
    - {chain_path}
    containing the certificate chain
    - {key_path}
    containing the signed certificates private key"
        ),
        Output::Der => writeln!(
            stdout,
            "created {n_der_files} der files:
    - {cert_path}, 
    containing the signed certificate
    - {key_path}
    containing the signed certificates private key

    - chain files each containing part of the certificate chain:
    {der_chain_files}"
        ),
    }
    .unwrap()
}
