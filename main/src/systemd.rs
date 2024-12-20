use color_eyre::eyre::{Context, Result};
use color_eyre::eyre;
use std::process::Command;

pub fn systemctl(args: &[&'static str], service: &str) -> Result<()> {
    let output = Command::new("systemctl")
        .args(args)
        .arg(service)
        .output()
        .wrap_err("Could not run systemctl")?;

    if output.status.success() {
        return Ok(());
    }

    let reason = String::from_utf8(output.stderr).unwrap();
    Err(eyre::eyre!("{reason}").wrap_err("Systemctl returned an error"))
}
