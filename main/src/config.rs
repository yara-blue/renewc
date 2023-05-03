use std::path::PathBuf;
use std::str::FromStr;

use crate::diagnostics;

use self::args::RenewArgs;

mod args;
pub use args::{Commands, InstallArgs, OutputConfig};

#[derive(clap::ValueEnum, Debug, Clone, Default, PartialEq, Eq)]
/// How to store the output.
///
/// After a certificate has been issued we have three outputs. Our signed
/// certificate. A certificate chain, it contains all the certificates
/// a client needs to check if our signed certificate is authentic. Our
/// certificates private key.
pub enum Output {
    /// Use PEM encoding. Store the chain, the signed certificate and the private
    /// key in the same file.
    ///
    /// Amongst others needed by: Haproxy
    Pem,

    /// Use PEM encoding. Store the certificate chain and signed certificate in the
    /// same file. Keep the private key in another.
    ///
    /// Amongst others needed by: Nginx and Apache
    #[default]
    PemSeperateKey,
    /// Use PEM encoding. Store the signed certificate and private key in the
    /// same file and the chain in another.
    PemSeperateChain,
    /// Use PEM encoding. Store the signed certificate, private key and chain
    /// all in their own file.
    PemAllSeperate,

    /// Use DER encoding. Store each certificate of the chain, the signed certificate
    /// and its private key in their own file.
    Der,

    #[cfg(feature = "derchain")]
    PKCS12,
    #[cfg(feature = "derchain")]
    PKCS12SeperateKey,
    #[cfg(feature = "derchain")]
    PKCS12SeperateChain,
    #[cfg(feature = "derchain")]
    PKCS12AllSeperate,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct Config {
    pub(crate) domains: Vec<String>,
    pub(crate) email: Vec<String>,
    pub production: bool,
    pub(crate) port: u16,
    pub output: args::OutputConfig,
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
            output: args.output,
            reload: args.reload,
            renew_early: args.renew_early,
            overwrite_production: args.overwrite_production,
            non_interactive: false,
            diagnostics: diagnostics::Config::default(),
        }
    }
}

// TODO: dont pass outputconfig to 
// run/renew only to store on disk function <03-05-23, dvdsk>
impl args::OutputConfig {
    fn test() -> Self {
        Self {
            output: Output::default(),
            certificate_path: PathBuf::from_str("test").unwrap(),
            key_path: None,
            chain_path: None,
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
            output: args::OutputConfig::test(),
            reload: None,
            renew_early: false,
            overwrite_production: false,
            non_interactive: true,
            diagnostics: diagnostics::Config::test(),
        }
    }
}
