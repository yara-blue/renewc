#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::io::Write;

use color_eyre::owo_colors::OwoColorize;
// use owo_colors::Stream;

use color_eyre::eyre::{self, Context};

pub mod cert;
pub mod renew;
pub mod systemd;
pub mod util;
pub mod diagnostics;
pub mod config;

pub use config::Config;
use config::Format;

macro_rules! warn {
    ($stream:expr, $($arg:tt)*) => { 
        // writeln!($stream, "{}", format_args!($($arg)*).if_supports_color(Stream::Stdout, |text| text.red())).unwrap()    
        writeln!($stream, "{}", format_args!($($arg)*).red()).unwrap()    
    };
}

macro_rules! info {
    ($stream:expr, $($arg:tt)*) => { 
        // writeln!($stream, "{}", format_args!($($arg)*).if_supports_color(Stream::Stdout, |text| text.green())).unwrap()
        writeln!($stream, "{}", format_args!($($arg)*).green()).unwrap()
    };
}

/// during integration testing we do not want to hit lets encrypts backend 
/// by passing the ACME implentation we can test other functionality. 
#[async_trait::async_trait]
pub trait ACME {
    async fn renew(&self, config: &Config, debug: bool) -> eyre::Result<cert::Signed>;
}

pub async fn run(acme_impl: impl ACME, stdout: &mut impl Write, config: &Config, debug: bool) -> eyre::Result<Option<Vec<u8>>> {

    if let Some(cert) = cert::get_info(&config.path)? {
        match (config.production, cert.staging, cert.should_renew()) {
            (false, true, _) => {
                warn!(stdout, "Requesting Staging cert, certificates will not be valid");
            }
            (false, false, _) if cert.is_expired() => {
                warn!(stdout, "Requesting Staging cert. Overwriting expired production certificate. Certificate will not be valid");
            }
            (false, false, _) => {
                let question = "Found still valid production cert, continuing will overwrite it with a staging certificate";
                if !config.overwrite_production && exit_requested(stdout, &config, question) {
                    return Ok(None);
                }
                warn!(stdout, "Requesting Staging cert, certificates will not be valid");
            }
            (true, true, _) => {
                info!(stdout, "Requesting production cert, existing certificate is staging");
            }
            (true, false, true) => {
                if cert.is_expired() {
                warn!(stdout, "Renewing production cert: existing certificate expired {} days, {} hours ago", cert.since_expired().whole_days(), cert.since_expired().whole_hours());
                } else {
                warn!(stdout, "Renewing production cert: existing certificate expires soon: {} days, {} hours", 
                      cert.expires_in.whole_days(), 
                      cert.expires_in.whole_hours());
                }
            }
            (true, false, false) => {
                info!(stdout, "Production cert not yet due for renewal, expires in: {} days, {} hours", 
                      cert.expires_in.whole_days(), 
                      cert.expires_in.whole_hours());
                if !config.renew_early {
                    info!(stdout, "Quiting, you can force renewal using --renew-early");
                    return Ok(None);
                }
            }
        }
    }

    let signed = acme_impl.renew(&config, debug).await?;
    let encoded = match config.format {
        Format::PemChain => signed.pem().wrap_err("PEM encoding failed")?,
        Format::DerChain => signed.der().wrap_err("DER encoding failed")?,
    };
    Ok(Some(encoded))
}

#[must_use]
fn exit_requested(w: &mut impl Write, config: &Config, question: &str) -> bool {
    use is_terminal::IsTerminal;

    info!(w, "{}", question);

    if config.non_interactive || !std::io::stdin().is_terminal() {
        warn!(w, "Need user confirmation however no user input possible");
        return true; // user cant confirm 
    }

    info!(w, "Continue? y/n");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();
    if let Some('y') = buf.chars().next() {
        info!(w, "Quiting, user requested exit");
        true
    } else {
        false
    }
}
