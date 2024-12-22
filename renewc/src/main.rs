use std::io::Write;

use clap::Parser;
use color_eyre::eyre::{self, Context};
use renewc::cert::Signed;
use renewc::Config;

use renewc::config::Commands;
use renewc::renew::InstantAcme;
use renewc::{cert, run};

mod install;
mod systemd;

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about = "Certificate renewal, with advanced diagnostics without installing anything",
    long_about = "This as a renewal tool that runs without install and does not need anything installed. If anything goes south during renewal it does not just report an error. It will try and find out what is wrong and give you a detailed report."
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
    #[clap(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    color_eyre::config::HookBuilder::default()
        .display_env_section(cli.debug)
        .display_location_section(cli.debug)
        .install()
        .unwrap();

    let debug = cli.debug || cli.command.debug();
    setup_tracing(debug);

    let mut stdout = std::io::stdout();
    match cli.command {
        Commands::Run(args) => {
            let config = Config::try_from(args)?;
            let Some(certs): Option<Signed<pem::Pem>> =
                run(&mut InstantAcme {}, &mut stdout, &config, debug).await?
            else {
                return Ok(());
            };
            cert::store::on_disk(&config, certs, &mut stdout)
                .wrap_err("Could not write out certificates")?;
            if let Some(service) = &config.reload {
                renewc::info!(&mut stdout, "reloading systemd service: {}", service);
                systemd::systemctl(&["reload"], service)
                    .wrap_err_with(|| "Could not reload ".to_owned() + service)?
            }
        }
        Commands::Install(args) => {
            let question = "Missing `--production` argument, certificates produced by \
                            service or job will not be valid";
            if !args.run.production {
                if exit_requested(&mut stdout, &question) {
                    return Ok(());
                }
            }
            install::perform(args)?;
        }
        Commands::Uninstall => {
            install::undo().wrap_err("failed to uninstall")?;
        }
    }
    Ok(())
}

#[must_use]
fn exit_requested(w: &mut impl std::io::Write, question: &str) -> bool {
    use std::io::IsTerminal;
    renewc::warn!(w, "{}", question);

    if !std::io::stdin().is_terminal() {
        renewc::error!(w, "Need user confirmation however no user input possible");
        return true; // user cant confirm
    }

    renewc::warn!(w, "Continue? y/n");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();
    if let Some('y') = buf.chars().next() {
        false
    } else {
        renewc::info!(w, "Quitting, user requested exit");
        true
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn setup_tracing(debug: bool) {
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    let filter = if debug {
        "renewc=debug,warn"
    } else {
        "renewc=warn"
    };

    let filter = filter::EnvFilter::builder().parse(filter).unwrap();

    let fmt = fmt::layer().pretty().with_line_number(true);

    let _ignore_err = tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .try_init();
}
