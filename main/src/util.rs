use color_eyre::eyre::Context;
use color_eyre::{Result, eyre};

/// # Errors 
/// returns an error if the string does not represent hours:minuts
pub fn try_to_time(s: &str) -> Result<time::Time> {
    let (h, m) = s
        .split_once(':')
        .ok_or_else(|| eyre::eyre!("Hours and minutes must be separated by :"))?;
    let h = h.parse().wrap_err("Could not parse hour")?;
    let m = m.parse().wrap_err("Could not parse minute")?;
    time::Time::from_hms(h, m, 0).wrap_err("Hour or minute not possible")
}
