use color_eyre::Report;
use itertools::Itertools;
use libproc::libproc::proc_pid;
use netstat2;
use netstat2::SocketInfo;
use std::fmt::Display;

#[derive(Debug)]
pub(crate) struct PortUser {
    pub(crate) name: String,
    #[allow(dead_code)]
    /// we use it as we use the Debug impl
    pub(crate) path: String,
}

impl Display for PortUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("- `{}`\n\t\tpath: {}", self.name, self.path))
    }
}

pub(crate) type ErrorString = String;

#[derive(Debug)]
pub(crate) struct Errors {
    pub(crate) resolving_name: Vec<(Pid, ErrorString)>,
    pub(crate) quering_socket: Vec<netstat2::error::Error>,
}

pub(crate) type Pid = i32;

pub(crate) fn users(port: u16) -> Result<(Vec<PortUser>, Errors), Report> {
    let (pids, mut errors) = port_pids(port)?;
    let (users, name_errs): (Vec<_>, Vec<_>) = pids
        .into_iter()
        .map(|pid| pid.try_into().unwrap())
        .map(|pid| {
            proc_pid::name(pid).map_err(|e| (pid, e)).and_then(|name| {
                proc_pid::pidpath(pid)
                    .map(|path| PortUser { name, path })
                    .map_err(|e| (pid, e))
            })
        })
        .partition_result();

    errors.resolving_name = name_errs;
    Ok((users, errors))
}

fn port_pids(port: u16) -> Result<(Vec<u32>, Errors), Report> {
    use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

    let tcp_port = |sock: &SocketInfo| {
        let ProtocolSocketInfo::Tcp(ref info) = sock.protocol_socket_info else {
        panic!("should not get Upd info with protocol flags set to TCP only");
    };
        info.local_port
    };

    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP;

    let (socks, errs): (Vec<_>, Vec<_>) =
        netstat2::iterate_sockets_info(af_flags, proto_flags)?.partition_result();

    let pids = socks
        .into_iter()
        .filter(|sock| tcp_port(sock) == port)
        .flat_map(|sock| sock.associated_pids)
        .collect();

    Ok((
        pids,
        Errors {
            resolving_name: Vec::new(),
            quering_socket: errs,
        },
    ))
}
