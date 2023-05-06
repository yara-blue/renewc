use color_eyre::eyre::{self, Context};

use crate::config::InstallArgs;

mod systemd;

pub fn perform(args: InstallArgs) -> eyre::Result<()> {
    systemd::write_service().wrap_err("Could not write systemd service")?;
    systemd::write_timer(&args).wrap_err("Could not write systemd timer")?;
    systemd::enable().wrap_err("Could not enable service and timer")
}

pub fn undo() -> eyre::Result<()> {
    systemd::disable().wrap_err("Could not disable service and timer")?;
    systemd::remove_units().wrap_err("Could not remove service and timer")
}

pub fn reload(service: &str) -> eyre::Result<()> {
    systemd::systemctl(&["reload"], service)
        .wrap_err_with(|| "Could not reload ".to_owned() + service)
}
