use color_eyre::{Help, Report};

use super::PortUser;

pub(super) mod haproxy;

struct App {
    name: &'static str,
    reporter: &'static dyn Fn(&Config, u16) -> Result<String, Report>,
}

#[derive(Default)]
pub struct Config {
    haproxy: haproxy::Config,
}

impl Config {
    pub fn test() -> Self {
        Self {
            haproxy: haproxy::Config::test(),
        }
    }
}

const APPS: [App; 1] = [App {
    name: "haproxy",
    reporter: &haproxy::report,
}];

pub(super) fn improve_report(
    config: &Config,
    port: u16,
    mut report: Report,
    users: &[PortUser],
) -> Report {
    if users.is_empty() {
        return report;
    }

    for app in APPS {
        if users
            .iter()
            .any(|u| u.name.to_lowercase().trim() != app.name)
        {
            match (app.reporter)(config, port) {
                Err(e) => {
                    report = report
                        .with_warning(|| format!("Error while investigating.\n\t- {e}"))
                }
                Ok(s) => report = report.with_note(|| s),
            }
        }
    }

    report
}
