use std::collections::HashMap;
use std::fs;

use color_eyre::eyre::{self, Context};
use color_eyre::Report;
use haproxy_config::config::{Frontend, Listen};
use haproxy_config::{parse_sections, Config};

const CONFIG_PATH: &'static str = "/etc/haproxy/haproxy.cfg";

pub fn report(bound_port: u16) -> Result<String, Report> {
    let file = fs::read_to_string(CONFIG_PATH).wrap_err("Could not read haproxy cfg")?;
    let sections = parse_sections(&file).wrap_err("Could not parse haproxy cfg")?;
    let config = Config::try_from(&sections).wrap_err("Could not parse haproxy cfg")?;

    let ports = forwarded_ports(config, bound_port)?;
    Ok(format!("haproxy is forwarding {bound_port} to port(s): {ports:?}"))
}

pub fn forwarded_ports(config: Config, bound_port: u16) -> Result<Vec<u16>, Report> {
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

    let possible_ports = match (frontend, listen) {
        (None, None) => Vec::new(),
        (Some(_), Some(_)) => {
            return Err(eyre::eyre!(
                "Incorrect haproxy config, a listen and frontend section bind to the same port"
            ))
        }
        (Some(frontend), None) => frontend_ports(frontend, second_frontend, &backend_ports)?,
        (None, Some(listen)) => listen_ports(listen, second_listen)?,
    };

    Ok(possible_ports)
}

fn listen_ports(listen: Listen, second: Option<Listen>) -> Result<Vec<u16>, Report> {
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
    second: Option<Frontend>,
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
        let config = Config::try_from(&sections).unwrap();
        let ports = forwarded_ports(config, 80).unwrap();

        assert_eq!(ports, [34320]);
        
    }
}
