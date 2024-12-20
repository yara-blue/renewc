use color_eyre::eyre::{self, Context};
use service_install::schedule::Schedule;
use service_install::{install_system, tui};

use renewc::config::InstallArgs;

pub fn perform(args: InstallArgs) -> eyre::Result<()> {
    let schedule = Schedule::Daily(args.time.0);
    let steps = install_system!()
        .current_exe()
        .wrap_err("Could not get path to current exe")?
        .name(env!("CARGO_PKG_NAME"))
        .on_schedule(schedule)
        .prepare_install()
        .wrap_err("Could not prepare installation")?;
    tui::install::start(steps, true).wrap_err("Installation failed")?;

    Ok(())
}

pub fn undo() -> eyre::Result<()> {
    let _ = install_system!()
        .current_exe()
        .wrap_err("Could not get path to current exe")?
        .name(env!("CARGO_PKG_NAME"))
        .prepare_remove()
        .wrap_err("Could not prepare for removal")?
        .remove()
        .map_err(|e| eyre::eyre!(e).wrap_err("failed to remove"))?;
    Ok(())
}
