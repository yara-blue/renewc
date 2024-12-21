use std::collections::HashSet;
use std::io::Write;

use cert::info::Info;
use itertools::Itertools;

use crate::{cert, Config};

#[macro_export]
macro_rules! warn {
    ($stream:expr, $($arg:tt)*) => {
        // writeln!($stream, "{}", format_args!($($arg)*).if_supports_color(Stream::Stdout, |text| text.red())).unwrap()
        writeln!($stream, "{}", owo_colors::OwoColorize::yellow(&format_args!($($arg)*))).unwrap()
    };
}

#[macro_export]
macro_rules! info {
    ($stream:expr, $($arg:tt)*) => {
        // writeln!($stream, "{}", format_args!($($arg)*).if_supports_color(Stream::Stdout, |text| text.green())).unwrap()
        writeln!($stream, "{}", owo_colors::OwoColorize::green(&format_args!($($arg)*))).unwrap()
    };
}

macro_rules! error {
    ($stream:expr, $($arg:tt)*) => {
        // writeln!($stream, "{}", format_args!($($arg)*).if_supports_color(Stream::Stdout, |text| text.green())).unwrap()
        writeln!($stream, "{}", owo_colors::OwoColorize::bright_red(&format_args!($($arg)*))).unwrap()
    };
}
pub use crate::info;
pub use crate::warn;

pub enum CheckResult {
    Refuse {
        status: Option<String>,
        warning: &'static str,
    },
    Accept {
        status: String,
    },
    NoCert,
    Warn {
        warning: &'static str,
    },
}

impl CheckResult {
    fn accept(status: impl Into<String>) -> Self {
        CheckResult::Accept {
            status: status.into(),
        }
    }

    fn refuse_without_status(warning: &'static str) -> Self {
        CheckResult::Refuse {
            status: None,
            warning,
        }
    }

    fn refuse(status: impl Into<String>, warning: &'static str) -> Self {
        CheckResult::Refuse {
            status: Some(status.into()),
            warning,
        }
    }
}

pub fn given_existing(
    config: &Config,
    cert: &Option<Info>,
    stdout: &mut impl Write,
) -> CheckResult {
    let Some(cert) = cert else {
        return CheckResult::NoCert;
    };

    let new_domains: HashSet<_> = config.domains.iter().collect();
    let prev_domains: HashSet<_> = cert.names.iter().collect();
    let missing = prev_domains.difference(&new_domains).map(|s| s.as_str());
    let n_missing = missing.clone().count();
    let missing: String = Itertools::intersperse_with(missing, || "\n\t-").collect();

    if !missing.is_empty() {
        let question = if n_missing == 1 {
            format!("Certificate will not be valid for (sub)domain that is currently valid, that (sub)domain is: {missing}")
        } else {
            format!("Certificate will not be valid for (sub)domains that are currently valid, these are:\n{missing}")
        };
        if exit_requested(stdout, config, &question) {
            return CheckResult::refuse_without_status("Not renewing, while domains are missing");
        }
    }

    match (config.production, cert.staging, cert.should_renew()) {
        (false, true, _) => {
            CheckResult::accept("Requesting staging cert, certificates will not be valid")
        }
        (false, false, _) if cert.is_expired() => {
            CheckResult::accept("Requesting staging cert. Overwriting expired production certificate. Certificate will not be valid")
        }
        (false, false, _) => {
            let question = "Found still valid production cert, continuing will overwrite it with a staging certificate";
            if !config.overwrite_production && exit_requested(stdout, config, question) {
                return CheckResult::refuse_without_status("Not overwriting valid production cert");
            }
            CheckResult::accept ("Requesting Staging cert, certificates will not be valid")
        }
        (true, true, _) => {
            CheckResult::accept("Requesting production cert, existing certificate is staging")
        }
        (true, false, true) => {
            if cert.is_expired() {
                CheckResult::Accept{ status: format!(
                    "Renewing production cert: existing certificate expired {} days, {} hours ago",
                    cert.since_expired().whole_days(),
                    cert.since_expired().whole_hours() % 24)}
            } else {
                let status = format!("Renewing production cert: existing certificate expires soon: {} days, {} hours", 
                  cert.expires_in.whole_days(),
                  cert.expires_in.whole_hours() % 24);

                CheckResult::accept(status)
            }
        }
        (true, false, false) => {
            let status = format!(
                "Production cert not yet due for renewal, expires in: {} days, {} hours",
                cert.expires_in.whole_days(),
                cert.expires_in.whole_hours() % 24,
            );
            if config.renew_early {
                CheckResult::accept(status)
            } else {
                CheckResult::refuse(status, "Quitting, you can force renewal using --renew-early")
            }
        }
    }
}

#[must_use]
fn exit_requested(w: &mut impl Write, config: &Config, question: &str) -> bool {
    use std::io::IsTerminal;
    info!(w, "{}", question);

    if config.non_interactive || !std::io::stdin().is_terminal() {
        error!(w, "Need user confirmation however no user input possible");
        return true; // user cant confirm
    }

    info!(w, "Continue? y/n");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).unwrap();
    if let Some('y') = buf.chars().next() {
        false
    } else {
        info!(w, "Quitting, user requested exit");
        true
    }
}
