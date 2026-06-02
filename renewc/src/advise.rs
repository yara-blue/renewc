use std::collections::HashSet;
use std::io::Write;

use cert::info::Info;
use itertools::Itertools;

use crate::cert::info::{CertSource, ShouldRenew};
use crate::config::{RenewEarly, ReplaceProd, RequestTo};
use crate::{Config, cert};

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

#[macro_export]
macro_rules! error {
    ($stream:expr, $($arg:tt)*) => {
        // writeln!($stream, "{}", format_args!($($arg)*).if_supports_color(Stream::Stdout, |text| text.green())).unwrap()
        writeln!($stream, "{}", owo_colors::OwoColorize::bright_red(&format_args!($($arg)*))).unwrap()
    };
}
pub use crate::error;
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

pub fn given_existing(config: &Config, existing: Info, stdout: &mut impl Write) -> CheckResult {
    let new_domains: HashSet<_> = config.domains.iter().collect();
    let prev_domains: HashSet<_> = existing.domains.iter().collect();
    let missing = prev_domains.difference(&new_domains).map(|s| s.as_str());
    let n_missing = missing.clone().count();
    let missing: String = Itertools::intersperse_with(missing, || "\n\t-").collect();

    if !missing.is_empty() {
        let question = if n_missing == 1 {
            format!(
                "Certificate will not be valid for (sub)domain that is currently valid, that (sub)domain is: {missing}"
            )
        } else {
            format!(
                "Certificate will not be valid for (sub)domains that are currently valid, these are:\n{missing}"
            )
        };
        if exit_requested(stdout, config, &question) {
            return CheckResult::refuse_without_status("Not renewing while domains are missing");
        }
    }

    match (
        config.request_to,
        existing.from,
        existing.should_renew(),
    ) {
        (RequestTo::Staging, CertSource::Staging, _) => {
            CheckResult::accept("Requesting staging cert, certificates will not be valid")
        }
        (RequestTo::Staging, CertSource::Production, _) if existing.is_expired() => {
            CheckResult::accept(
                "Requesting staging cert. Overwriting expired production certificate. Certificate will not be valid",
            )
        }
        (RequestTo::Staging, CertSource::Production, _) => {
            let question = "Found still valid production cert, continuing will overwrite it with a staging certificate";
            if let ReplaceProd::No = config.replace_production
                && exit_requested(stdout, config, question)
            {
                return CheckResult::refuse_without_status("Not overwriting valid production cert");
            }
            CheckResult::accept("Requesting Staging cert, certificates will not be valid")
        }
        (RequestTo::Production, CertSource::Staging, _) => {
            CheckResult::accept("Requesting production cert, existing certificate is staging")
        }
        (RequestTo::Production, CertSource::Production, ShouldRenew::Yes) => {
            if existing.is_expired() {
                CheckResult::Accept {
                    status: format!(
                        "Renewing production cert: existing certificate expired {} days, {} hours ago",
                        existing.since_expired().whole_days(),
                        existing.since_expired().whole_hours() % 24
                    ),
                }
            } else {
                let status = format!(
                    "Renewing production cert: existing certificate expires soon: {} days, {} hours",
                    existing.expires_in.whole_days(),
                    existing.expires_in.whole_hours() % 24
                );

                CheckResult::accept(status)
            }
        }
        (RequestTo::Production, CertSource::Production, ShouldRenew::No) => {
            let status = format!(
                "Production cert not yet due for renewal expires in: {} days, {} hours",
                existing.expires_in.whole_days(),
                existing.expires_in.whole_hours() % 24,
            );
            if let RenewEarly::Yes = config.renew_early {
                CheckResult::accept(status)
            } else {
                CheckResult::refuse(
                    status,
                    "Quitting, you can force renewal using --renew-early",
                )
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
