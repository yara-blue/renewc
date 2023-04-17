use color_eyre::{Help, Report};

use super::port::PortUser;

pub(super) mod haproxy;

pub struct Feedback {
    note: String,
    suggestion: Option<String>,
}

impl Feedback {
    fn new(note: impl Into<String>, suggestion: Option<impl Into<String>>) -> Option<Feedback> {
        Some(Self {
            note: note.into(),
            suggestion: suggestion.map(|s| s.into()),
        })
    }
}

type Findings = Option<Feedback>;
struct App {
    name: &'static str,
    #[allow(clippy::type_complexity)]
    reporter: &'static dyn Fn(&Config, u16) -> Result<Findings, Report>,
}

#[derive(Default, Debug, Clone)]
pub struct Config {
    pub haproxy: haproxy::Config,
}

impl Config {
    #[must_use]
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
            .any(|u| u.name.to_lowercase().trim() == app.name)
        {
            match (app.reporter)(config, port) {
                Err(e) => {
                    report = report.with_warning(|| format!("Error while investigating.\n\t- {e}"));
                }
                Ok(Some(Feedback {
                    note,
                    suggestion: Some(s),
                })) => report = report.with_note(|| note).with_suggestion(|| s),
                Ok(Some(Feedback {
                    note,
                    suggestion: None,
                })) => report = report.with_note(|| note),
                Ok(None) => (),
            }
        }
    }

    report
}
