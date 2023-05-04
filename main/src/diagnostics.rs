use std::string::ToString;

use color_eyre::{Help, Report};
use itertools::Itertools;

mod applications;
mod port;
pub mod reachable;
pub use applications::Config;

use crate::config;

fn root() -> bool {
    use libproc::libproc::proc_pid;
    proc_pid::am_root()
}

fn insufficent_permission(port: u16) -> bool {
    port <= 1024 && !root()
}

pub(crate) fn cant_bind_port(config: &config::Config, e: hyper::Error) -> Report {
    match build_report(&config.diagnostics, e, config.port) {
        Ok(r) => r,
        Err(r) => r.wrap_err("Could not deduce cause of error"),
    }
}

fn build_report<E>(config: &Config, e: E, port: u16) -> Result<Report, Report>
where
    E: std::error::Error + Sync + Send + 'static,
{
    let mut r = Report::new(e);
    if insufficent_permission(port) {
        r = r.wrap_err("insufficient permission to attach to port");
        r = r.with_suggestion(|| "You normally need sudo to attach to ports below 1025");
        r = r.with_note(|| format!("port: {port}"));
    }

    let (users, errs) = port::users(port)?;
    if !users.is_empty() || !errs.resolving_name.is_empty() {
        r = r.wrap_err("The port is already in use");

        if !users.is_empty() {
            let list = users.iter().map(ToString::to_string).join(",\n\t");
            r = r.with_note(|| format!("The port is being used by:\n\t{list}"));
            r = applications::improve_report(config, port, r, &users);
        }

        if !errs.resolving_name.is_empty() {
            r = r.with_warning(|| {
                format!("Could not resolve name for pids: {:?}", errs.resolving_name)
            });
        }

        if !errs.quering_socket.is_empty() {
            r = r.with_warning(|| {
                format!(
                    "Could not check all sockets: {:?}",
                    errs.quering_socket.is_empty()
                )
            });
        }
    }

    Ok(r)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn find_port_users() {
        let port_binder = TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_port = port_binder.local_addr().unwrap().port();

        let (users, errs) = port::users(bound_port).unwrap();

        assert!(errs.quering_socket.is_empty(), "{:?}", errs.quering_socket);
        assert!(errs.resolving_name.is_empty(), "{:?}", errs.resolving_name);
        assert_eq!(users.len(), 1, "{users:?}");
    }

    #[test]
    fn detect_insufficent_perm() {
        assert!(insufficent_permission(1024));
        assert!(!insufficent_permission(1025));
    }
}
