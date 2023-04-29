use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::format::PemItem;
use super::io::{derive_path, name};
use super::load::Encoding;
use super::Signed;
use color_eyre::eyre::{self, Context};
use itertools::Itertools;

use crate::config::{Output, OutputConfig};
use crate::Config;

fn write_cert(encoding: Encoding, certificate: PemItem, operation: Operation) -> eyre::Result<()> {
    let bytes = match encoding {
        Encoding::PEM => certificate.into_bytes(),
        Encoding::DER => certificate.der(),
    };
    match operation {
        Operation::Append(path) => {
            let mut file = fs::OpenOptions::new().append(true).open(path)?;
            return file
                .write_all(&bytes)
                .wrap_err("Could not append signed certificate to pem file");
        }
        Operation::Create(path) => {
            let mut file = fs::File::create(path)?;
            file.write_all(&bytes)
                .wrap_err("could not create signed certificate file")
        }
    }
}

fn write_key(encoding: Encoding, private_key: PemItem, operation: Operation) -> eyre::Result<()> {
    let bytes = match encoding {
        Encoding::PEM => private_key.into_bytes(),
        Encoding::DER => private_key.der(),
    };

    match operation {
        Operation::Append(path) => {
            let mut file = fs::OpenOptions::new().append(true).open(path)?;
            return file
                .write_all(&bytes)
                .wrap_err("Could not append private key to pem file");
        }
        Operation::Create(path) => {
            let mut file = fs::File::create(path)?;
            file.write_all(&bytes)
                .wrap_err("could not create private key file")
        }
    }
}

fn write_chain(encoding: Encoding, chain: Vec<PemItem>, path: &Path) -> eyre::Result<()> {
    if encoding == Encoding::DER {
        for (i, cert) in chain.into_iter().enumerate() {
            let bytes = cert.der();
            let path = path.with_file_name(format!("{i}_chain.der"));

            let mut file = fs::File::create(path)?;
            file.write_all(&bytes)
                .wrap_err("could not create certificate chain file")?;
        }
        return Ok(());
    }

    let bytes: Vec<u8> =
        Itertools::intersperse(chain.iter().map(PemItem::as_bytes), "\n".as_bytes())
            .flatten()
            .copied()
            .collect();
    let mut file = fs::File::create(path)?;
    file.write_all(&bytes)
        .wrap_err("could not create certificate chain file")
}

enum Operation<'a> {
    Append(&'a Path),
    Create(&'a Path),
}

pub fn on_disk(config: &Config, signed: Signed) -> eyre::Result<()> {
    use Operation::*;
    let cert_path = cert_path(config)?;
    let key_path = key_path(config)?;
    let chain_path = chain_path(config)?;

    let encoding = Encoding::from(&config.output.output);
    let Signed {
        certificate,
        private_key,
        chain,
    } = signed;

    match config.output.output {
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

fn cert_path(config: &Config) -> eyre::Result<PathBuf> {
    let OutputConfig {
        output,
        certificate_path,
        ..
    } = &config.output;

    let encoding = Encoding::from(output);

    Ok(if certificate_path.is_dir() {
        derive_path(
            certificate_path,
            &name(&config.domains)?,
            "cert",
            encoding.extension(),
        )
    } else {
        certificate_path.clone()
    })
}

fn chain_path(config: &Config) -> eyre::Result<PathBuf> {
    let OutputConfig {
        output,
        certificate_path,
        chain_path,
        ..
    } = &config.output;

    let encoding = Encoding::from(output);
    Ok(match chain_path {
        None => derive_path(
            certificate_path,
            &name(&config.domains)?,
            "chain",
            encoding.extension(),
        ),
        Some(path) => path.clone(),
    })
}

fn key_path(config: &Config) -> eyre::Result<PathBuf> {
    let OutputConfig {
        output,
        certificate_path,
        key_path,
        ..
    } = &config.output;

    let encoding = Encoding::from(output);
    Ok(match key_path {
        None => derive_path(
            certificate_path,
            &name(&config.domains)?,
            "key",
            encoding.extension(),
        ),
        Some(path) => path.clone(),
    })
}
