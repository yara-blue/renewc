use color_eyre::eyre::{self, Context};
use renewc::name;
use service_install::schedule::Schedule;
use service_install::{install_system, tui};

use renewc::config::InstallArgs;

fn format_args(args: InstallArgs) -> Vec<String> {
    let mut res = Vec::new();
    let args = args.run;

    for domain in args.domain {
        res.push("--domain".to_string());
        res.push(domain);
    }

    for email in args.email {
        res.push("--email".to_string());
        res.push(email);
    }

    if args.production {
        res.extend(["--production".to_string()]);
    }

    res.extend(["--port".to_string(), args.port.to_string()]);
    if let Some(reload) = args.reload {
        res.extend(["--reload".to_string(), reload]);
    }
    if args.renew_early {
        res.push("--renew-early".to_string());
    }
    if args.force {
        res.push("--force".to_string());
    }
    if args.overwrite_production {
        res.push("--overwrite-production".to_string());
    }
    if args.debug {
        res.push("--debug".to_string());
    }
    let args = args.output_config;
    res.extend(["--output".to_string(), args.output.to_string()]);

    let format = |p: &std::path::Path| {
        p.to_str()
            .expect("only utf8 is supported for arguments")
            .to_string()
    };
    res.extend([
        "--certificate-path".to_string(),
        format(&args.certificate_path),
    ]);
    if let Some(key_path) = args.key_path {
        res.extend(["--key-path".to_string(), format(&key_path)]);
    }
    if let Some(chain_path) = args.chain_path {
        res.extend(["--chain-path".to_string(), format(&chain_path)]);
    }

    res
}

pub fn perform(args: InstallArgs) -> eyre::Result<()> {
    let schedule = Schedule::Daily(args.time.0);

    let steps = install_system!()
        .current_exe()
        .wrap_err("Could not get path to current exe")?
        .overwrite_existing(true)
        .service_name(service_name(&args)?)
        .on_schedule(schedule)
        .args(format_args(args))
        .prepare_install()
        .wrap_err("Could not prepare installation")?;
    tui::install::start(steps, true).wrap_err("Installation failed")?;

    Ok(())
}

fn service_name(args: &InstallArgs) -> eyre::Result<String> {
    Ok(if let Some(service_name) = &args.service_name {
        service_name.to_owned()
    } else {
        format!(
            "{}{}",
            env!("CARGO_PKG_NAME"),
            name(&args.run.domain)
                .wrap_err("could not figure out certificate file name")
                .wrap_err("Could not generate service name")?
        )
    })
}

pub fn undo() -> eyre::Result<()> {
    let _ = install_system!()
        .current_exe()
        .wrap_err("Could not get path to current exe")?
        .prepare_remove()
        .wrap_err("Could not prepare for removal")?
        .remove()
        .map_err(|e| eyre::eyre!(e).wrap_err("failed to remove"))?;
    Ok(())
}
