use std::io::{ErrorKind, Write};

use crate::config::{Encoding, OutputConfig};
use crate::Config;
use color_eyre::eyre::{self, Context};
use color_eyre::Help;
use tracing::instrument;

use super::format::{Der, Label, PemItem};
use super::{MaybeSigned, Signed};

use super::io::read_any_file;

// TODO: remove Option, report errors upstream as warnings <03-05-23, dvdsk>
#[instrument(level = "debug", skip(config, stdout), ret)]
pub fn from_disk<P: PemItem>(
    config: &Config,
    stdout: &mut impl Write,
) -> eyre::Result<Option<Signed<P>>> {
    let Some(MaybeSigned {
        certificate,
        private_key,
        mut chain,
    }) = load_certificate(&config.output_config)
        .wrap_err("Failed to load certificates from disk")?
    else {
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
        tracing::info!("Certificate chain in certificates currently on disk not found.");
        write!(stdout, "Found existing certificate however could not find a certificate chain. This can be a problem for some applications. Renewal will create a chain file, can proceed without problems and is recommended.").unwrap();
        chain = Vec::new();
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
        output, chain_path, ..
    } = &config.output_config;

    let encoding = Encoding::from(output);
    match encoding {
        Encoding::DER => {
            let mut chain = Vec::new();
            for i in 0.. {
                let path = chain_path
                    .as_path()
                    .with_file_name(format!("{i}_chain.der"));
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
            let Some(bytes) = read_any_file(chain_path.as_path())? else {
                return Ok(Vec::new());
            };
            P::chain_from_pem(bytes)
        }

        Encoding::PKCS12 => {
            todo!()
        }
    }
}

#[instrument(level = "debug", skip(config), err)]
fn load_seperate_private_key<P: PemItem>(config: &Config) -> eyre::Result<Option<P>> {
    let OutputConfig {
        output, key_path, ..
    } = &config.output_config;
    let encoding = Encoding::from(output);

    let Some(bytes) = read_any_file(key_path.as_path())? else {
        return Ok(None);
    };

    Ok(Some(match encoding {
        Encoding::PEM => P::from_pem(bytes, Label::PrivateKey)?,
        Encoding::DER => Der::from_bytes(bytes).to_pem(Label::PrivateKey),
        Encoding::PKCS12 => todo!(),
    }))
}

#[instrument(level = "debug", ret)]
fn load_certificate<P: PemItem>(config: &OutputConfig) -> eyre::Result<Option<MaybeSigned<P>>> {
    let OutputConfig {
        output, cert_path, ..
    } = &config;

    let Some(bytes) = read_any_file(cert_path.as_path())? else {
        return Ok(None);
    };

    let encoding = Encoding::from(output);
    match encoding {
        Encoding::PEM => MaybeSigned::from_pem(bytes)
            .map(Option::Some)
            .wrap_err("Could not decode pem"),
        Encoding::DER => Ok(Some(MaybeSigned::<P> {
            certificate: Der::from_bytes(bytes).to_pem(Label::Certificate),
            private_key: None,
            chain: Vec::new(),
        })),
        Encoding::PKCS12 => todo!(),
    }
}
