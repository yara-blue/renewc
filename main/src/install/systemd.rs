#![allow(clippy::missing_errors_doc)]
// ^needed as we have a lib and a main, pub crate would
// only allow access from the lib. However since the lib is not
// public it makes no sense to document errors.

use color_eyre::eyre::{Context, Result};
use color_eyre::{eyre, Help};
use std::fs;
use std::io::Write;
use std::os::unix::prelude::PermissionsExt;
use std::process::Command;
use std::time::{Instant, Duration};
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
After=network.target

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
fn timer_str(hour: u8, minute: u8) -> String {
    let run = format!("*-*-* {hour}:{minute}:10");

    format!(
        "[Unit]
        Description=Renew letsencrypt certificates
        [Timer]
        OnCalendar={run}
        AccuracySec=60
        [Install]
        WantedBy=timers.target
        "
    )
}

// Since we want to run without any user logged in we are a system service
macro_rules! path {
    ($ext:literal) => {
        concat!("/etc/systemd/system/", env!("CARGO_PKG_NAME"), ".", $ext)
    };
}

pub fn write_service() -> Result<()> {
    let service = service_str().wrap_err("Could not construct service")?;
    let path = path!("service");
    let mut f = std::fs::File::create(path).with_note(|| format!("path: {path}"))?;
    f.write_all(service.as_bytes())
        .with_note(|| format!("path: {path}"))?;
    let meta = f.metadata()?;
    let mut perm = meta.permissions();
    perm.set_mode(0o664);
    Ok(())
}

pub fn write_timer(args: &InstallArgs) -> Result<()> {
    let timer = timer_str(args.time.0.hour(), args.time.0.minute());

    let path = path!("timer");
    let mut f = std::fs::File::create(path).with_note(|| format!("path: {path}"))?;
    f.write_all(timer.as_bytes())
        .with_note(|| format!("path: {path}"))?;
    let meta = f.metadata()?;
    let mut perm = meta.permissions();
    perm.set_mode(0o664);
    Ok(())
}

pub fn remove_units() -> Result<()> {
    fs::remove_file(path!("timer")).wrap_err("Error removing timer")?;
    fs::remove_file(path!("service")).wrap_err("Error removing service")
}

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
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(1) {
        if state == is_active(service)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    if let true = state {
        Err(eyre::eyre!("Time out waiting for activation"))
    } else {
        Err(eyre::eyre!("Time out waiting for deactivation"))
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
