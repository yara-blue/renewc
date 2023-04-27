use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::io::{derive_path, name};
use super::load::Encoding;
use super::Signed;
use color_eyre::eyre::{self, Context};

use crate::config::{OutputConfig, Output};
use crate::Config;

fn write_cert(config: &Config, signed: &Signed, tomato: Tomato) -> eyre::Result<()> {
    match tomato {
        Tomato::Appended(path) => {
            let mut file = fs::OpenOptions::new().append(true).open(path)?;
            return file
                .write_all(signed.certificate.as_bytes())
                .wrap_err("Could not append signed certificate to pem file");
        }
        Tomato::Created(path) => {
            let mut file = fs::File::create(path)?;
            file.write_all(signed.certificate.as_bytes())
                .wrap_err("could not create signed certificate file")
        }
    }
}

fn write_key(config: &Config, signed: &Signed, tomato: Tomato) -> eyre::Result<()> {
    match tomato {
        Tomato::Appended(path) => {
            let mut file = fs::OpenOptions::new().append(true).open(path)?;
            return file
                .write_all(signed.certificate.as_bytes())
                .wrap_err("Could not append signed certificate to pem file");
        }
        Tomato::Created(path) => {
            let mut file = fs::File::create(path)?;
            file.write_all(signed.certificate.as_bytes())
                .wrap_err("could not create signed certificate file")
        }
    }
}

fn write_chain(config: &Config, signed: &Signed, path: &Path) -> eyre::Result<()> {
    let bytes: Vec<u8> = signed
        .chain
        .iter()
        .flat_map(String::as_bytes)
        .copied()
        .collect();

    let mut file = fs::File::create(path)?;
    file.write_all(&bytes)
        .wrap_err("could not create certificate chain file")
}

enum Tomato<'a> {
    Appended(&'a Path),
    Created(&'a Path),
}

pub fn on_disk(config: &Config, signed: &Signed) -> eyre::Result<()> {
    use Tomato::*;
    let cert_path = cert_path(config)?;
    let key_path = key_path(config)?;
    let chain_path = chain_path(config)?;

    match config.output.output {
        Output::Pem => {
            write_chain(config, signed, &cert_path)?;
            write_cert(config, signed, Appended(&cert_path))?;
            write_key(config, signed, Appended(&cert_path))?;
        }
        Output::PemSeperateKey => {
            write_chain(config, signed, &cert_path)?;
            write_cert(config, signed, Appended(&cert_path))?;
            write_key(config, signed, Created(&key_path))?;
        }
        Output::PemSeperateChain => {
            write_chain(config, signed, &chain_path)?;
            write_cert(config, signed, Created(&cert_path))?;
            write_key(config, signed, Appended(&cert_path))?;
        }
        Output::PemAllSeperate | Output::Der => {
            write_chain(config, signed, &chain_path)?;
            write_cert(config, signed, Created(&cert_path))?;
            write_key(config, signed, Created(&key_path))?;
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
