use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use color_eyre::eyre::{self, Context};
use color_eyre::Report;
use haproxy_config::config::{Frontend, Listen};
use haproxy_config::parse_sections;
use haproxy_config::Config as HaConfig;
use tracing::{debug, instrument};

use super::{Feedback, Findings};

#[derive(Debug)]
pub struct Config {
    pub path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            path: PathBuf::from("/etc/haproxy/haproxy.cfg"),
        }
    }
}

impl Config {
    pub fn test() -> Self {
        Self {
            path: PathBuf::from("src/diagnostics/applications/haproxy.cfg"),
        }
    }
}

#[instrument(level = "debug", skip(config))]
pub fn report(config: &super::Config, bound_port: u16) -> Result<Findings, Report> {
    let file = match fs::read_to_string(&config.haproxy.path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let mut path = std::env::current_dir().unwrap_or_default();
            path.push(&config.haproxy.path);
            return Err(e).wrap_err_with(|| format!("failed to read {}", path.display()));
        }
        Err(e) => return Err(e).wrap_err_with(|| "failed to read haproxy config".to_string()),
    };
    let sections = parse_sections(&file).wrap_err("Could not parse haproxy cfg")?;
    let config = HaConfig::try_from(&sections).wrap_err("Could not parse haproxy cfg")?;

    let ports = forwarded_ports(config, bound_port)?;
    if ports.is_empty() {
        debug!("Could not find where the bound port was forwarded to");
        return Ok(None);
    }

    Ok(if ports.len() > 1 {
        Feedback::new(
            format!("haproxy is forwarding port {bound_port} to port(s): {ports:?}"),
            Some(concat!(
                "try calling ",
                env!("CARGO_PKG_NAME"),
                " with `--port <port>` using one of these ports"
            )),
        )
    } else {
        Feedback::new(
            format!("haproxy is forwarding port {bound_port} to: {}", ports[0]),
            Some(format!(
                "try calling {} with: `--port {}`",
                env!("CARGO_PKG_NAME"),
                ports[0]
            )),
        )
    })
}

#[instrument(level = "debug", skip(config))]
pub fn forwarded_ports(config: HaConfig, bound_port: u16) -> Result<Vec<u16>, Report> {
    debug!("{config:#?}");
    let backend_ports: HashMap<String, u16> = config
        .backends
        .into_iter()
        .flat_map(|(name, b)| {
            b.servers
                .into_iter()
                .filter_map(|s| s.addr.port)
                .map(move |p| (name.clone(), p))
        })
        .collect();

    let mut frontends = config
        .frontends
        .into_values()
        .filter(|f| f.bind.addr.port == Some(bound_port));
    let frontend = frontends.next();
    let second_frontend = frontends.next();
    let mut listens = config
        .listen
        .into_values()
        .filter(|l| l.bind.addr.port == Some(bound_port));
    let listen = listens.next();
    let second_listen = listens.next();

    debug!("frontend: {frontend:?}, listen: {listen:?}");
    let possible_ports = match (frontend, listen) {
        (None, None) => Vec::new(),
        (Some(_), Some(_)) => {
            return Err(eyre::eyre!(
                "Incorrect haproxy config, a listen and frontend section bind to the same port"
            ))
        }
        (Some(frontend), None) => frontend_ports(frontend, &second_frontend, &backend_ports)?,
        (None, Some(listen)) => listen_ports(listen, &second_listen)?,
    };

    Ok(possible_ports)
}

fn listen_ports(listen: Listen, second: &Option<Listen>) -> Result<Vec<u16>, Report> {
    if second.is_some() {
        return Err(eyre::eyre!(
            "Incorrect haproxy, only one listen section can bind to the same port"
        ));
    }

    Ok(listen
        .servers
        .into_iter()
        .filter_map(|s| s.addr.port)
        .collect())
}

fn frontend_ports(
    frontend: Frontend,
    second: &Option<Frontend>,
    backend_ports: &HashMap<String, u16>,
) -> Result<Vec<u16>, Report> {
    if second.is_some() {
        return Err(eyre::eyre!(
            "Incorrect haproxy, only one frontend section can bind to the same port"
        ));
    }

    frontend
        .backends
        .into_iter()
        .map(|b| {
            backend_ports.get(&b.name).copied().ok_or_else(|| {
                eyre::eyre!(
                    "Incorrect haproxy config, backend '{}' in frontend '{}' does not exist",
                    b.name,
                    frontend.name
                )
            })
        })
        .collect::<Result<_, _>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_letsencrypt_forward() {
        let file = include_str!("haproxy.cfg");
        let sections = parse_sections(file).unwrap();
        let config = HaConfig::try_from(&sections).unwrap();
        let ports = forwarded_ports(config, 80).unwrap();

        assert_eq!(ports, [34320]);
    }
}
