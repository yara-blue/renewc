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

mod write;

#[derive(Debug)]
pub struct Signed {
    pub private_key: String,
    pub cert_chain: String,
}

fn read_in(path: &Path) -> eyre::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => {
            tracing::debug!("No certificate already at {}", path.display());
            Ok(None)
        }
        Err(e) => Err(e)
            .wrap_err("Could not check for existing certificate")
            .suggestion("Check if the path is correct")
            .with_note(|| format!("path: {path:?}")),
        Ok(bytes) => Ok(Some(bytes)),
    }
}

fn parse_and_analyze(bytes: &[u8]) -> eyre::Result<Info> {
    // try parse bytes as pem certificate chain, if its not a pem return an
    // empty vec
    if let Some(cert_info) = analyze_pem(bytes)? {
        return Ok(cert_info);
    }

    analyze_der(bytes)
}

pub fn analyze_der(bytes: &[u8]) -> Result<Info, color_eyre::Report> {
    let mut parser = X509CertificateParser::new();
    let mut certs = Vec::new();
    loop {
        let (rest, cert) = parser.parse(bytes).unwrap();
        certs.push(cert);
        if rest.is_empty() {
            break;
        }
    }
    analyze(&certs)
}

pub fn analyze_pem(bytes: &[u8]) -> Result<Option<Info>, color_eyre::Report> {
    let mut pems = Vec::new();
    for (i, pem) in Pem::iter_from_buffer(bytes).enumerate() {
        match pem {
            // we need this dance around with a pem
            // vector as x509 cert borrows pem.
            // thus we cant simple parse the x509 in the loop
            Ok(pem) => pems.push(pem),
            Err(PEMError::InvalidHeader) if i == 0 => {
                // not a pem file
                return Ok(None);
            }
            Err(PEMError::IOError(e)) if i == 0 && e.kind() == ErrorKind::InvalidData => {
                // not a pem file
                return Ok(None);
            }
            Err(e) => Err(e).wrap_err("Could not parse pem")?,
        };
    }

    let certs: Vec<_> = pems.iter().map(Pem::parse_x509).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Ok(None);
    }
    analyze(&certs).map(Option::Some)
}

/// extract public cert and private key from a PEM encoded cert
pub fn get_info(path: &Path) -> eyre::Result<Option<Info>> {
    let Some(bytes) = read_in(path)? else {
        return Ok(None);
    };

    let info = parse_and_analyze(&bytes)?;
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
pub fn analyze(certs: &[X509Certificate]) -> eyre::Result<Info> {
    let mut staging = false;
    let mut expires_in = Duration::MAX;
    let mut expires_at = u64::MAX;

    for cert in certs {
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
    }

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
        let cert = rcgen::generate_simple_self_signed(["example.org".into()]).unwrap();
        let der = cert.serialize_der().unwrap();

        parse_and_analyze(&der).unwrap();
    }

    #[test]
    fn parse_pem() {
        let cert = rcgen::generate_simple_self_signed(["example.org".into()]).unwrap();
        let pem = cert.serialize_pem().unwrap();

        parse_and_analyze(pem.as_bytes()).unwrap();
    }
}
