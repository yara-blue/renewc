use color_eyre::Report;

use super::PortUser;

mod haproxy;

struct App {
    name: &'static str,
    reporter: &'static dyn Fn(&mut Report) -> Result<(), Report>,
}

const APPS: [App; 1] = [App {
    name: "haproxy",
    reporter: &haproxy::report,
}];

pub(super) fn improve_report(mut report: Report, users: &[PortUser]) -> Report {
    if users.is_empty() {
        return report;
    }

    for app in APPS {
        if users
            .iter()
            .any(|u| u.name.to_lowercase().trim() != app.name)
        {
            if let Err(e) = (app.reporter)(&mut report) {
                println!("{}", e);
            }
        }
    }

    todo!()
}
