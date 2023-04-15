use color_eyre::eyre;
use color_eyre::eyre::{Context, Result};
use std::fs;
use std::process::Command;
use std::time::Duration;
use std::{env, thread};

use crate::config::InstallArgs;

// String should be written to a .service file
fn service_str() -> Result<String> {
    let path = env::current_exe().wrap_err(concat!(
        "Could not get ",
        env!("CARGO_PKG_NAME"),
        "'s binary location"
    ))?;

    let working_dir = path.parent().unwrap().to_str().unwrap();
    let bin_path = path.to_str().unwrap();
    let mut args = std::env::args().skip(1).map(|s| {
        if s.contains(' ') {
            format!("\"{s}\" ")
        } else {
            format!("{s} ")
        }
    });

    let mut service_args = String::new();
    while let Some(arg) = args.next() {
        let mut arg = arg.as_str();
        if arg == "--time " {
            args.next(); // skip time arg
            continue;
        }
        if arg == "install " {
            arg = "run ";
        }
        service_args.push_str(arg);
    }

    Ok(format!(
        "[Unit]
Description=Renew letsencrypt certificates
[Service]
Type=oneshot
WorkingDirectory={working_dir}
ExecStart={bin_path} {service_args}
[Install]
WantedBy=multi-user.target
",
    ))
}

// String should be written to a .timer file
fn timer_str(hour: u8, minute: u8) -> Result<String> {
    let run = format!("*-*-* {}:{}:10", hour, minute);

    Ok(format!(
        "[Unit]
Description=Renew letsencrypt certificates
[Timer]
OnCalendar={run}
AccuracySec=60
[Install]
WantedBy=timers.target
"
    ))
}

macro_rules! unit_path {
    ($ext:literal) => {
        concat!("/etc/systemd/system/", env!("CARGO_PKG_NAME"), ".", $ext)
    };
}

pub fn write_service() -> Result<()> {
    let service = service_str().wrap_err("Could not construct service")?;
    let path = unit_path!("service");
    fs::write(path, service).wrap_err_with(|| format!("could not write file to: {path}"))?;
    Ok(())
}

pub fn write_timer(args: &InstallArgs) -> Result<()> {
    let time = super::util::try_to_time(&args.time)?;
    let timer = timer_str(time.hour(), time.minute()).wrap_err("Could not construct timer")?;

    let path = unit_path!("timer");
    fs::write(path, timer).wrap_err_with(|| format!("could not write file to: {path}"))
}

pub fn remove_units() -> Result<()> {
    fs::remove_file(unit_path!("timer")).wrap_err("Error removing timer")?;
    fs::remove_file(unit_path!("service")).wrap_err("Error removing service")
}

pub(crate) fn systemctl(args: &[&'static str], service: &str) -> Result<()> {
    let output = Command::new("systemctl")
        .args(args)
        .arg(service)
        .output()
        .wrap_err("Could not run systemctl")?;

    if !output.status.success() {
        let reason = String::from_utf8(output.stderr).unwrap();
        Err(eyre::eyre!("{reason}").wrap_err("Systemctl returned an error"))
    } else {
        Ok(())
    }
}

fn timer() -> &'static str {
    concat!(env!("CARGO_PKG_NAME"), ".timer")
}

fn is_active(service: &str) -> Result<bool> {
    let output = Command::new("systemctl")
        .arg("is-active")
        .arg(service)
        .output()
        .wrap_err("Could not run systemctl")?;

    Ok(output.status.code().unwrap() == 0)
}

fn wait_for(service: &str, state: bool) -> Result<()> {
    for _ in 0..20 {
        if state == is_active(service)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    match state {
        true => Err(eyre::eyre!("Time out waiting for activation")),
        false => Err(eyre::eyre!("Time out waiting for deactivation")),
    }
}

pub fn enable() -> Result<()> {
    systemctl(&["enable", "--now"], timer())?;
    wait_for(timer(), true).wrap_err("Timer was not activated")?;
    Ok(())
}

pub fn disable() -> Result<()> {
    systemctl(&["disable", "--now"], timer())?;
    wait_for(timer(), false).wrap_err("Timer was not deactivated")?;
    Ok(())
}
