use std::io::ErrorKind;

use crate::config::{Output, OutputConfig};
use crate::Config;
use color_eyre::eyre::{self, Context};
use color_eyre::Help;
use tracing::instrument;

use super::format::{Der, Label, PemItem};
use super::{MaybeSigned, Signed};

use super::io::{derive_path, name, read_any_file};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    PEM,
    DER,
    #[cfg(feature = "derchain")]
    PKCS12,
}

impl Encoding {
    pub(crate) fn extension(&self) -> &'static str {
        match self {
            Encoding::PEM => "pem",
            Encoding::DER => "der",
            #[cfg(feature = "derchain")]
            Encoding::PKCS12 => "pkcs12",
        }
    }
}

impl From<&Output> for Encoding {
    fn from(output: &Output) -> Self {
        match output {
            Output::Pem => Encoding::PEM,
            Output::PemSeperateKey => Encoding::PEM,
            Output::PemSeperateChain => Encoding::PEM,
            Output::PemAllSeperate => Encoding::PEM,
            Output::Der => Encoding::DER,
        }
    }
}

#[instrument(level = "debug", skip(config), ret)]
pub fn from_disk<P: PemItem>(config: &Config) -> eyre::Result<Option<Signed<P>>> {
    let Some(MaybeSigned { certificate, private_key, mut chain }) = load_certificate(config)? else {
        return Ok(None);
    };

    let private_key = match private_key {
        Some(key) => key,
        None => match load_seperate_private_key(config)? {
            Some(key) => key,
            None => return Ok(None),
        },
    };
    if chain.is_empty() {
        chain = load_seperate_chain(config)?;
    }

    if chain.is_empty() {
        tracing::info!("Certificate chain from disk is empty");
        return Ok(None);
    }

    Ok(Some(Signed {
        certificate,
        private_key,
        chain,
    }))
}

#[instrument(level = "debug", skip(config), err)]
fn load_seperate_chain<P: PemItem>(config: &Config) -> eyre::Result<Vec<P>> {
    let OutputConfig {
        output,
        certificate_path,
        chain_path,
        ..
    } = &config.output;
    let encoding = Encoding::from(output);
    let path = match chain_path {
        None => derive_path(
            certificate_path,
            &name(&config.domains)?,
            "chain",
            encoding.extension(),
        ),
        Some(path) => path.clone(),
    };

    match encoding {
        Encoding::DER => {
            let mut chain = Vec::new();
            for i in 0.. {
                let path = path.with_file_name(format!("{i}_chain.der"));
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == ErrorKind::NotFound => break,
                    Err(e) => Err(e)
                        .wrap_err("Could not read certificate chain file")
                        .with_note(|| format!("path: {path:?}"))?,
                };
                let der = Der::from_bytes(bytes);
                chain.push(der.to_pem(Label::Certificate));
            }
            Ok(chain)
        }

        Encoding::PEM => {
            let Some(bytes) = read_any_file(&path)? else {
                return Ok(Vec::new());
            };
            P::chain_from_pem(bytes)
        }
    }
}

#[instrument(level = "debug", skip(config), err)]
fn load_seperate_private_key<P: PemItem>(config: &Config) -> eyre::Result<Option<P>> {
    let OutputConfig {
        output,
        certificate_path,
        key_path,
        ..
    } = &config.output;
    let encoding = Encoding::from(output);

    let path = match key_path {
        None => derive_path(
            certificate_path,
            &name(&config.domains)?,
            "key",
            encoding.extension(),
        ),
        Some(path) => path.clone(),
    };

    let Some(bytes) = read_any_file(&path)? else {
        return Ok(None);
    };

    Ok(Some(match encoding {
        Encoding::PEM => P::from_pem(bytes, Label::PrivateKey)?,
        Encoding::DER => Der::from_bytes(bytes).to_pem(Label::PrivateKey),
    }))
}

#[instrument(level = "debug", skip(config), ret)]
fn load_certificate<P: PemItem>(config: &Config) -> eyre::Result<Option<MaybeSigned<P>>> {
    let OutputConfig {
        output,
        certificate_path,
        ..
    } = &config.output;
    let encoding = Encoding::from(output);
    let path = if certificate_path.is_dir() {
        derive_path(
            &certificate_path,
            &name(&config.domains)?,
            "cert",
            encoding.extension(),
        )
    } else {
        certificate_path.clone()
    };

    let Some(bytes) = read_any_file(&path)? else {
        return Ok(None);
    };

    match encoding {
        Encoding::PEM => MaybeSigned::from_pem(bytes).map(Option::Some),
        Encoding::DER => Ok(Some(MaybeSigned::<P> {
            certificate: Der::from_bytes(bytes).to_pem(Label::Certificate),
            private_key: None,
            chain: Vec::new(),
        })),
    }
}
