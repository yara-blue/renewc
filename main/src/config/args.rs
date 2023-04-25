use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Renew certificates now
    Run(RenewArgs),
    /// Create and enable renew-certs system service.
    Install(InstallArgs),
    /// Disable and remove renew-certs system service.
    Uninstall,
}

impl Commands {
    #[must_use]
    pub fn debug(&self) -> bool {
        match self {
            Commands::Run(args) => args.debug,
            Commands::Install(args) => args.run.debug,
            Commands::Uninstall => false,
        }
    }
}

#[derive(Parser, Debug)]
pub struct InstallArgs {
    /// time at which refresh should run
    #[clap(long, default_value = "04:00")]
    pub(crate) time: String,

    #[clap(flatten)]
    pub run: RenewArgs,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug)]
pub struct RenewArgs {
    /// domain(s) request certificates for multiple subdomains
    /// by passing this argument multiple times with various domains
    /// note the base domain must be the same in all
    #[clap(long, required = true)]
    domain: Vec<String>,

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
    /// /etc/ssl/certs
    #[clap(long)]
    path: PathBuf,

    /// Name of the certificate, if unspecified the shortest
    /// domain is used
    name: Option<String>,

    /// The format to store the key in
    #[clap(value_enum, default_value_t = Format::PEM)]
    pub format: Format,

    /// Store the certificates private key after the certificate. This means the private key is 
    /// stored in the same file as the certificate independent of the include-key flag.
    ///
    /// By default the key is kept seperate from the chain in its own file with name ending in _key
    #[clap(long, default_value_t = false)]
    pub include_key: bool,

    /// Where to store the certificates private key when its stored seperate from the other output (the default)
    #[clap(long)]
    pub key_path: Option<PathBuf>,

    /// Store the certificate chain seperate from the certificate in a file with name ending in _chain
    #[clap(long, default_value_t = false)]
    pub seperate_chain: bool,

    /// Where to store the certificate chain when its stored seperate from the other output (the default)
    #[clap(long)]
    pub chain_path: Option<PathBuf>,

    /// Systemd service to reload after renewal
    reload: Option<String>,

    /// Renew a certificate even if its not due yet
    #[clap(long, default_value_t = false)]
    renew_early: bool,

    /// Request a staging certificate even if that overwrites a
    /// valid production certificate
    #[clap(long, default_value_t = false)]
    overwrite_production: bool,

    #[clap(short, long)]
    debug: bool,
}

#[derive(clap::ValueEnum, Debug, Clone, Default)]
pub enum Format {
    /// PEM is a ascii serialization of keys thats easy to copy. It is the most used 
    /// format. A PEM file can contain one or more certificates and optionally a private 
    /// key. Used with Apache, Nginx and HaProxy. 
    #[default]
    PEM,
    /// Der is a binary encoding. It can only encode a single certificate not chains.
    /// For der encoded certificate chains use PKCS12.
    DER,
    #[cfg(feature = "derchain")]
    /// PKCS12 is a container for one or more certificates and possibly the private key in 
    /// DER format. Typically used with Java keystores
    PKCS12,
}
