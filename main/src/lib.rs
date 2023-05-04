#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::io::Write;

use cert::format::PemItem;
use cert::info::Info;
use color_eyre::eyre;

pub mod cert;
pub mod config;
pub mod diagnostics;
pub mod renew;
pub mod systemd;
pub mod ui;
pub mod util;

pub use config::Config;
use owo_colors::OwoColorize;
use ui::CheckResult;

/// during integration testing we do not want to hit lets encrypts backend
/// by passing the ACME implentation we can test other functionality.
#[async_trait::async_trait]
pub trait ACME {
    async fn renew<P: PemItem>(
        &self,
        config: &Config,
        debug: bool,
    ) -> eyre::Result<cert::Signed<P>>;
}

fn warn(stdout: &mut impl Write, s: &str) {
    let s = s.red().to_string() + "\n";
    stdout.write_all(s.as_bytes()).unwrap();
}

fn info(stdout: &mut impl Write, s: &str) {
    let s = s.green().to_string() + "\n";
    stdout.write_all(s.as_bytes()).unwrap();
}

pub async fn run<P: PemItem>(
    acme_impl: &mut impl ACME,
    stdout: &mut impl Write,
    config: &Config,
    debug: bool,
) -> eyre::Result<Option<cert::Signed<P>>> {
    'check_existing: {
        if !config.force {
            let cert = match Info::from_disk(config) {
                Ok(Some(cert)) => cert,
                Ok(None) => break 'check_existing,
                Err(e) => {
                    writeln!(stdout, "Warning: renew advise impossible").unwrap();
                    for (i, err) in e.chain().enumerate() {
                        ui::warn!(stdout, "   {i}: {err}");
                    }
                    writeln!(
                        stdout,
                        "Note: {}",
                        "This might mean the previous certificate is corrupt or broken".blue()
                    )
                    .unwrap();
                    break 'check_existing;
                }
            };

            match ui::precheck(config, &cert, stdout) {
                CheckResult::Refuse {
                    status: Some(status),
                    warning,
                } => {
                    info(stdout, &status);
                    warn(stdout, warning);
                    return Ok(None);
                }
                CheckResult::Refuse {
                    status: None,
                    warning,
                } => {
                    warn(stdout, warning);
                    return Ok(None);
                }
                CheckResult::Accept { status } => {
                    info(stdout, &status);
                }
            }
        }
    }

    let signed = acme_impl.renew(config, debug).await?;
    Ok(Some(signed))
}
