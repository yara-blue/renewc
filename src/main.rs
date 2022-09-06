use clap::Parser;
use color_eyre::eyre;

mod cert;
mod server;

#[derive(Parser, Debug)]
struct Args {
    /// Domains
    #[clap(long, required = true)]
    domains: Vec<String>,

    /// Contact info
    #[clap(long)]
    email: Vec<String>,

    /// Use Let's Encrypt production environment
    /// (see https://letsencrypt.org/docs/staging-environment/)
    #[clap(long)]
    prod: bool,

    /// External port 80 should be forwarded to this
    /// internal port
    #[clap(short, long, default_value = "80")]
    port: u16,

    #[clap(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install().unwrap();
    let args = Args::parse();

    setup_tracing(args.debug);

    let signed = cert::request(args.domains, args.port, args.debug).await?;
    Ok(())
}

pub fn setup_tracing(debug: bool) {
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    let filter = match debug {
        true => "info,tower_http=trace",
        false => "warn",
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
