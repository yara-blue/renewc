use std::io::Read;
use std::path::PathBuf;
use time::Duration;

use clap::{Parser, Subcommand};
use color_eyre::eyre::{self, Context};
use tracing::{info, warn};

mod cert;
mod renew;
mod server;
mod systemd;
mod util;

#[derive(Parser, Debug)]
pub struct InstallArgs {
    /// time at which refresh should run
    #[clap(long, default_value = "04:00")]
    time: String,

    #[clap(flatten)]
    run: RenewArgs,
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum Format {
    /// a PEM file containing both the required certificates and any associated private key
    /// compatible with HaProxy
    SinglePem,
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
    production: bool,

    /// External port 80 should be forwarded to this
    /// internal port
    #[clap(long, default_value_t = 80)]
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

#[derive(Subcommand, Debug)]
enum Commands {
    /// Renew certificates now
    Run(RenewArgs),
    /// Create and enable renew-certs system service.
    Install(InstallArgs),
    /// Disable and remove renew-certs system service.
    Uninstall,
}

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about,
    long_about = "Renew lets encrypt certificates. Can be ran manually with Run and Unlock or set up to trigger at given times using Install."
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
    #[clap(short, long)]
    debug: bool,
}

async fn run(args: RenewArgs, debug: bool) -> eyre::Result<()> {
    if let Some(existing) = cert::extract_combined(&args.path)? {
        let (expires_in, is_staging) = cert::analyze(existing)?;
        let expires_soon = expires_in < Duration::days(10);
        match (!args.production, is_staging, expires_soon) {
            (true, true, _) => {
                warn!("Requesting Staging cert, certificates will not be valid")
            }
            (true, false, _) => {
                println!("Found production cert, continuing will overwrite it with a staging certificate");
                println!("Continue? y/n");
                let mut buf = [0u8];
                std::io::stdin().read(&mut buf).unwrap();
                if buf[0] as char != 'y' {
                    info!("Quiting, user requested exit");
                    return Ok(());
                }
                warn!("Requesting Staging cert, certificates will not be valid")
            }
            (false, true, _) => {
                info!("Requesting production cert, existing certificate is staging")
            }
            (false, false, true) => {
                info!("Renewing production cert: existing certificate expires soon: {} days, {} hours", 
                      expires_in.whole_days(), 
                      expires_in.whole_hours())
            }
            (false, false, false) => {
                info!("Quiting: production cert not yet due for renewal, expires in: {} days, {} hours", 
                      expires_in.whole_days(), 
                      expires_in.whole_hours());
                return Ok(());
            }
        }
    }

    let signed = renew::request(args.domains, args.port, args.production, debug).await?;
    cert::write_combined(args.path, signed).wrap_err("Could not write out certificates")?;
    if let Some(service) = args.reload {
        systemd::systemctl(&["reload"], &service)
            .wrap_err_with(|| "Could not reload ".to_owned() + &service)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install().unwrap();
    let cli = Cli::parse();

    setup_tracing(cli.debug);

    match cli.command {
        Commands::Run(args) => run(args, cli.debug).await?,
        Commands::Install(args) => {
            if !args.run.production {
                warn!("Installing service that runs against staging-environment, certificates will not be valid");
            }
            systemd::write_service().wrap_err("Could not write systemd service")?;
            systemd::write_timer(&args).wrap_err("Could not write systemd timer")?;
            systemd::enable().wrap_err("Could not enable service and timer")?;
        }
        Commands::Uninstall => {
            systemd::disable().wrap_err("Could not disable service and timer")?;
            systemd::remove_units().wrap_err("Could not remove service and timer")?;
        }
    }
    Ok(())
}

pub fn setup_tracing(debug: bool) {
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    let filter = match debug {
        true => "debug,tower_http=trace",
        false => "info",
    };

    let filter = filter::EnvFilter::builder().parse(filter).unwrap();

    let fmt = fmt::layer()
        .pretty()
        .with_line_number(true)
        .with_test_writer();

    let _ignore_err = tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .try_init();
}
