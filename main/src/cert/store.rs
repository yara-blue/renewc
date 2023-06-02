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
fn write_cert(
    encoding: Encoding,
    certificate: impl PemItem,
    operation: Operation,
) -> eyre::Result<()> {
    let bytes = match encoding {
        Encoding::PEM => certificate.into_bytes(),
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
        Encoding::PEM => private_key.into_bytes(),
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

#[instrument(level = "debug", skip(chain))]
fn write_chain<P: PemItem>(encoding: Encoding, chain: Vec<P>, path: &Path) -> eyre::Result<()> {
    if encoding == Encoding::DER {
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
        chain.into_iter().map(P::into_bytes),
        "\n".as_bytes().to_vec(),
    )
    .flatten()
    .collect();
    let mut file = fs::File::create(path)?;
    file.write_all(&bytes)
        .wrap_err("could not create certificate chain file")
}

#[derive(Debug)]
enum Operation<'a> {
    Append(&'a Path),
    Create(&'a Path),
}

#[instrument(level = "debug", skip(config, signed), ret)]
pub fn on_disk<P: PemItem>(config: &Config, signed: Signed<P>) -> eyre::Result<()> {
    use Operation::{Append, Create};
    let OutputConfig {
        output,
        cert_path,
        key_path,
        chain_path,
    } = &config.output_config;

    let cert_path = cert_path.as_path();
    let key_path = key_path.as_path();
    let chain_path = chain_path.as_path();

    let encoding = Encoding::from(output);
    let Signed {
        certificate,
        private_key,
        chain,
    } = signed;

    match config.output_config.output {
        Output::Pem => {
            write_chain(encoding, chain, &cert_path)?;
            write_cert(encoding, certificate, Append(&cert_path))?;
            write_key(encoding, private_key, Append(&cert_path))?;
        }
        Output::PemSeperateKey => {
            write_chain(encoding, chain, &cert_path)?;
            write_cert(encoding, certificate, Append(&cert_path))?;
            write_key(encoding, private_key, Create(&key_path))?;
        }
        Output::PemSeperateChain => {
            write_chain(encoding, chain, &chain_path)?;
            write_cert(encoding, certificate, Create(&cert_path))?;
            write_key(encoding, private_key, Append(&cert_path))?;
        }
        Output::PemAllSeperate | Output::Der => {
            write_chain(encoding, chain, &chain_path)?;
            write_cert(encoding, certificate, Create(&cert_path))?;
            write_key(encoding, private_key, Create(&key_path))?;
        }
    }

    Ok(())
}
