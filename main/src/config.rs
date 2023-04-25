use std::path::PathBuf;

use color_eyre::eyre::bail;

use crate::diagnostics;

use self::args::RenewArgs;

mod args;

#[derive(Debug, Clone)]
pub enum Format {
    Pem {
        chain: PathBuf,
    },
    PemSeperateKey {
        dir: PathBuf,
    },
    PemSeperateChain {
        dir: PathBuf,
    },
    PemAllSeperate {
        dir: PathBuf,
    },

    Der {
        dir: PathBuf,
    },

    #[cfg(feature = "derchain")]
    PKCS12 {
        chain: PathBuf,
    },
    #[cfg(feature = "derchain")]
    PKCS12SeperateKey {
        dir: PathBuf,
    },
    #[cfg(feature = "derchain")]
    PKCS12SeperateChain {
        dir: PathBuf,
    },
    #[cfg(feature = "derchain")]
    PKCS12AllSeperate {
        dir: PathBuf,
    },
}

impl TryFrom<&RenewArgs> for Format {
    type Error = color_eyre::Report;

    fn try_from(args: &RenewArgs) -> Result<Self, Self::Error> {
        let RenewArgs {
            format,
            include_key,
            seperate_chain,
            ..
        } = args;
        match (format, include_key, seperate_chain) {
            (args::Format::PEM, true, true) => Ok(Format::PemSeperateChain { dir: todo!() }),
            (args::Format::PEM, true, false) => Ok(Format::Pem { chain: todo!() }),
            (args::Format::PEM, false, true) => Ok(Format::PemAllSeperate { dir: todo!() }),
            (args::Format::PEM, false, false) => Ok(Format::PemSeperateKey { dir: todo!() }),
            (args::Format::DER, true, _) => {
                bail!("can not include key, der can only encode a single certs or a single key")
            }
            (args::Format::DER, _, false) => {
                bail!("must seperate certs, der can only encode a single certs or a single key")
            }
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct Config {
    pub(crate) domains: Vec<String>,
    pub(crate) email: Vec<String>,
    pub production: bool,
    pub(crate) port: u16,
    pub format: Format,
    pub reload: Option<String>,
    pub(crate) renew_early: bool,
    pub(crate) overwrite_production: bool,
    /// do not ask questions
    pub non_interactive: bool,
    pub diagnostics: diagnostics::Config,
}

impl From<RenewArgs> for Config {
    fn from(args: RenewArgs) -> Self {
        Config {
            domains: args.domain,
            email: args.email,
            production: args.production,
            port: args.port,
            path: args.path,
            format: args.format,
            reload: args.reload,
            renew_early: args.renew_early,
            overwrite_production: args.overwrite_production,
            non_interactive: false,
            diagnostics: diagnostics::Config::default(),
        }
    }
}

impl Config {
    #[must_use]
    pub fn test(port: u16) -> Self {
        Config {
            domains: vec!["testdomain.org".into()],
            email: vec!["test_email".into()],
            production: false,
            port,
            path: PathBuf::from("tests/cert_path"),
            format: Format::default(),
            reload: None,
            renew_early: false,
            overwrite_production: false,
            non_interactive: true,
            diagnostics: diagnostics::Config::test(),
        }
    }
}
