use rand::{Rng, SeedableRng};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use time::Duration;
use tracing::instrument;
use x509_parser::nom::Parser;
use x509_parser::prelude::{PEMError, Pem, X509Certificate, X509CertificateParser};

use color_eyre::eyre::{self, Context};
use color_eyre::Help;

use crate::config;

pub mod load;

#[derive(Debug)]
pub struct MaybeSigned {
    // PEM encoded
    pub certificate: String,
    // PEM encoded
    pub private_key: Option<String>,
    // PEM encoded
    pub chain: Option<String>,
}

#[derive(Debug)]
pub struct Signed {
    // PEM encoded
    pub certificate: String,
    // PEM encoded
    pub private_key: String,
    // PEM encoded
    pub chain: String,
}

impl TryFrom<MaybeSigned> for Signed {
    type Error = &'static str;

    fn try_from(signed: MaybeSigned) -> Result<Self, Self::Error> {
        Ok(Self {
            certificate: signed.certificate,
            private_key: signed.private_key.ok_or("missing private key")?,
            chain: signed.chain.ok_or("missing chain")?,
        })
    }
}

impl Signed {
    /// last certificate in full chain must be the domains certificate
    pub fn from_key_and_fullchain(
        private_key: String,
        mut full_chain: String,
    ) -> eyre::Result<Self> {
        let start_cert = full_chain
            .rfind("-----BEGIN CERTIFICATE-----")
            .ok_or_else(|| eyre::eyre!("No certificates in full chain!"))?;
        let certificate = full_chain.split_off(start_cert);
        let chain = full_chain;

        Ok(Self {
            private_key,
            certificate,
            chain,
        })
    }
}

/// extract public cert and private key from a PEM encoded cert
pub fn get_info(config: &config::Config) -> eyre::Result<Option<Info>> {
    let Some(signed) = load::from_disk(config)? else {
        return Ok(None);
    };
    let info = analyze(signed)?;
    Ok(Some(info))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Info {
    pub staging: bool,
    pub expires_in: Duration,
    // unix timestamp of expiration time
    // used to seed rng such that each randomness
    // only changes with a renewed certificate
    seed: u64,
}
impl Info {
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
pub fn analyze(signed: Signed) -> eyre::Result<Info> {
    let mut staging = false;
    let mut expires_in = Duration::MAX;
    let mut expires_at = u64::MAX;

    let cert = signed.certificate.as_bytes();
    let cert = Pem::iter_from_buffer(cert).next().unwrap()?;
    let cert = Pem::parse_x509(&cert)?;

    staging |= cert
        .issuer()
        .iter_organization()
        .map(|o| o.as_str().unwrap())
        .any(|s| s.contains("STAGING"));
    expires_in = expires_in.min(
        cert.validity()
            .time_to_expiration()
            .unwrap_or(Duration::ZERO),
    );
    expires_at = expires_at.min(
        cert.validity()
            .not_after
            .timestamp()
            .try_into()
            .expect("got negative timestamp from x509 certificate, this is a bug"),
    );

    Ok(Info {
        staging,
        expires_in,
        seed: expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_der() {
        // let cert = rcgen::generate_simple_self_signed(["example.org".into()]).unwrap();
        // let der = cert.serialize_der().unwrap();
        //
        // parse_and_analyze(&der).unwrap();
        panic!("test disabled");
    }

    #[test]
    fn parse_pem() {
        // let cert = rcgen::generate_simple_self_signed(["example.org".into()]).unwrap();
        // let pem = cert.serialize_pem().unwrap();
        //
        // parse_and_analyze(pem.as_bytes()).unwrap();
        panic!("test disabled");
    }
}
