use rand::{Rng, SeedableRng};

use time::Duration;
use tracing::instrument;
use x509_parser::prelude::Pem;

use color_eyre::eyre::{self, bail};

use crate::config;

use format::PemItem;

use self::format::Label;

pub mod format;
pub mod io;
pub mod load;
pub mod store;

#[derive(Debug)]
pub struct MaybeSigned {
    // PEM encoded
    pub(crate) certificate: PemItem,
    // PEM encoded
    pub(crate) private_key: Option<PemItem>,
    // PEM encoded
    pub(crate) chain: Vec<PemItem>,
}

#[derive(Debug)]
pub struct Signed {
    // PEM encoded
    pub(crate) certificate: PemItem,
    // PEM encoded
    pub(crate) private_key: PemItem,
    // List of PEM encoded
    pub(crate) chain: Vec<PemItem>,
}

impl TryFrom<MaybeSigned> for Signed {
    type Error = eyre::Report;

    fn try_from(signed: MaybeSigned) -> Result<Self, Self::Error> {
        if signed.chain.is_empty() {
            bail!("missing chain")
        }

        Ok(Self {
            certificate: signed.certificate,
            private_key: signed
                .private_key
                .ok_or_else(|| eyre::eyre!("missing private key"))?,
            chain: signed.chain,
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
        let certificate = PemItem::from_pem(full_chain.split_off(start_cert), Label::Certificate)?;

        let mut chain = Vec::new();
        while let Some(begin_cert) = full_chain.rfind("-----BEGIN CERTIFICATE-----") {
            chain.push(PemItem::from_pem(
                full_chain.split_off(begin_cert),
                Label::Certificate,
            )?);
        }

        if chain.is_empty() {
            bail!("No chain certificates in full chain")
        }

        let private_key = PemItem::from_pem(private_key, Label::PrivateKey)?;

        Ok(Self {
            private_key,
            certificate,
            chain,
        })
    }
}

impl MaybeSigned {
    pub(super) fn from_pem(bytes: Vec<u8>) -> eyre::Result<Self> {
        let mut pem = String::from_utf8(bytes)?;
        let start_key = pem.rfind("-----BEGIN PRIVATE KEY-----");
        let private_key = start_key
            .map(|i| pem.split_off(i))
            .map(|p| PemItem::from_pem(p, Label::PrivateKey))
            .transpose()?;

        let start_cert = pem.rfind("-----BEGIN CERTIFICATE-----");
        let certificate = start_cert
            .map(|i| pem.split_off(i))
            .ok_or(eyre::eyre!("Can no find a certificate"))?;
        let certificate = PemItem::from_pem(certificate, Label::Certificate)?;

        let chain = PemItem::chain(pem)?;

        Ok(MaybeSigned {
            certificate,
            private_key,
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
