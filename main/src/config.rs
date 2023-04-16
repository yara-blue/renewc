use std::path::PathBuf;

use clap::Parser;

use crate::diagnostics;

#[derive(clap::ValueEnum, Debug, Clone, Default)]
pub enum Format {
    /// a PEM file containing both the required certificates and any associated private key
    /// compatible with HaProxy
    #[default]
    SinglePem,
}

#[derive(Parser, Debug)]
pub struct InstallArgs {
    /// time at which refresh should run
    #[clap(long, default_value = "04:00")]
    pub(crate) time: String,

    #[clap(flatten)]
    pub run: RenewArgs,
}

#[derive(Parser, Debug)]
pub struct RenewArgs {
    /// Domains
    #[clap(long, required = true)]
    domains: Vec<String>,

    /// Contact info
    #[clap(long)]
    email: Vec<String>,

    /// Use Let's Encrypt production environment
    /// (see https://letsencrypt.org/docs/staging-environment/)
    #[clap(long)]
    pub production: bool,

    /// External port 80 should be forwarded to this
    /// internal port
    #[clap(long, default_value_t = 80, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,

    /// cert path including file name, for example
    /// /etc/ssl/certs/example.org.pem
    #[clap(long)]
    path: PathBuf,

    /// the format to store the key in
    #[clap(value_enum, default_value_t = Format::SinglePem)]
    format: Format,

    /// systemd service to reload after renewal
    reload: Option<String>,
}

pub struct Config {
    pub(crate) domains: Vec<String>,
    pub(crate) email: Vec<String>,
    pub(crate) production: bool,
    pub(crate) port: u16,
    pub(crate) path: PathBuf,
    pub(crate) format: Format,
    pub(crate) reload: Option<String>,
    pub diagnostics: diagnostics::Config,
}

impl From<RenewArgs> for Config {
    fn from(args: RenewArgs) -> Self {
        Config {
            domains: args.domains,
            email: args.email,
            production: args.production,
            port: args.port,
            path: args.path,
            format: args.format,
            reload: args.reload,
            diagnostics: diagnostics::Config::default(),
        }
    }
}

impl Config {
    #[must_use] pub fn test(port: u16) -> Self {
        Config {
            domains: vec!["testdomain.org".into()],
            email: vec!["test_email".into()],
            production: false,
            port,
            path: PathBuf::from("tests/cert_path"),
            format: Format::default(),
            reload: None,
            diagnostics: diagnostics::Config::test(),
        }
    }
}
