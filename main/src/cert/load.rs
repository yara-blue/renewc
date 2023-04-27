use crate::config::{Output, OutputConfig};
use crate::Config;
use color_eyre::eyre;

use super::{MaybeSigned, Signed};

mod der;
mod pem;

use super::io::{derive_path, name, read_any_file};

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

pub(super) fn from_disk(config: &Config) -> eyre::Result<Option<Signed>> {
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
        return Ok(None);
    }

    Ok(Some(Signed {
        certificate,
        private_key,
        chain,
    }))
}

fn load_seperate_chain(config: &Config) -> eyre::Result<Vec<String>> {
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

    let Some(bytes) = read_any_file(&path)? else {
        return Ok(Vec::new());
    };

    match encoding {
        Encoding::PEM => pem::chain_from_bytes(bytes),
        Encoding::DER => todo!(),
    }
}

fn load_seperate_private_key(config: &Config) -> eyre::Result<Option<String>> {
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

    match encoding {
        Encoding::PEM => pem::private_key(bytes),
        Encoding::DER => todo!(),
    }
}

fn load_certificate(config: &Config) -> eyre::Result<Option<MaybeSigned>> {
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
        Encoding::DER => MaybeSigned::from_der(bytes).map(Option::Some),
    }
}
