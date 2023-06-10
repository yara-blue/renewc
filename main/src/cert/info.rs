use std::io::Write;

use super::format::PemItem;
use super::{load, Signed};
use crate::config;

use color_eyre::eyre;
use rand::{self, Rng, SeedableRng};
use time::Duration;
use tracing::instrument;
use x509_parser::prelude::Pem;

#[derive(Debug, PartialEq, Eq)]
pub struct Info {
    pub staging: bool,
    pub expires_in: Duration,
    // unix timestamp of expiration time
    // used to seed rng such that each randomness
    // only changes with a renewed certificate
    pub(crate) seed: u64,
}

impl Info {
    pub fn from_disk(
        config: &config::Config,
        stdout: &mut impl Write,
    ) -> eyre::Result<Option<Self>> {
        let Some(signed) = load::from_disk::<pem::Pem>(config, stdout)? else {
            return Ok(None);
        };
        let info = analyze(signed)?;
        Ok(Some(info))
    }

    /// how far before the expiration date to renew a certificate
    #[instrument(ret, skip(self))]
    pub fn renew_period(&self) -> Duration {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.seed);
        let range = Duration::days(8)..Duration::days(10);
        let range = range.start.whole_seconds()..range.end.whole_seconds();
        let renew_period = rng.gen_range(range);
        Duration::seconds(renew_period)
    }

    pub(crate) fn since_expired(&self) -> Duration {
        self.expires_in.abs()
    }

    #[instrument(ret, skip(self))]
    pub(crate) fn should_renew(&self) -> bool {
        self.expires_in < self.renew_period()
    }

    #[instrument(ret, skip(self))]
    pub fn is_expired(&self) -> bool {
        self.expires_in <= Duration::seconds(0)
    }
}

/// returns number of days until the first certificate in the chain
/// expires and whether any certificate is from STAGING
#[instrument(ret)]
pub fn analyze(signed: Signed<impl PemItem>) -> eyre::Result<Info> {
    let cert = signed.certificate.as_bytes();
    let cert = Pem::iter_from_buffer(&cert).next().unwrap()?;
    let cert = Pem::parse_x509(&cert)?;

    let staging = cert
        .issuer()
        .iter_organization()
        .map(|o| o.as_str().unwrap())
        .any(|s| s.contains("STAGING"));
    let expires_in = cert
        .validity()
        .time_to_expiration()
        .unwrap_or(Duration::ZERO);
    let expires_at = cert
        .validity()
        .not_after
        .timestamp()
        .try_into()
        .expect("got negative timestamp from x509 certificate, this is a bug");

    Ok(Info {
        staging,
        expires_in,
        seed: expires_at,
    })
}
