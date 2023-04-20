use rand::{Rng, SeedableRng};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use time::Duration;

use color_eyre::eyre::{self, Context};
use color_eyre::Help;

#[derive(Debug)]
pub struct Signed {
    pub private_key: String,
    pub public_cert_chain: String,
}

pub fn write_combined(path: PathBuf, signed: Signed) -> eyre::Result<()> {
    let combined = signed.public_cert_chain + "\n" + &signed.private_key;
    fs::write(path, combined)?;
    Ok(())
}

/// extract public cert and private key from a PEM encoded cert
pub fn extract_combined(path: &Path) -> eyre::Result<Option<Signed>> {
    let combined = match fs::read_to_string(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e)
                .wrap_err("Could not check for existing certificate")
                .suggestion("Check if the path is correct")
                .with_note(|| format!("path: {path:?}"));
        }
        Ok(combined) => combined,
    };

    let mut lines = combined.lines();
    Ok(Some(Signed {
        public_cert_chain: lines
            .by_ref()
            .take_while(|l| !l.contains("PRIVATE KEY"))
            .map(|l| l.to_owned() + "\n")
            .collect(),
        private_key: std::iter::once("-----BEGIN PRIVATE KEY-----")
            .chain(lines)
            .map(|l| l.to_owned() + "\n")
            .collect(),
    }))
}

#[derive(Debug)]
pub struct CertInfo {
    pub staging: bool,
    pub expires_in: Duration,
    // unix timestamp of expiration time
    // used to seed rng such that each randomness
    // only changes with a renewed certificate
    seed: u64,
}
impl CertInfo {
    pub(crate) fn should_renew(&self) -> bool {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.seed);
        let range = Duration::days(8)..Duration::days(10);
        let range = range.start.whole_seconds()..range.end.whole_seconds();
        let renew_period = rng.gen_range(range);
        let renew_period = Duration::seconds(renew_period);

        self.expires_in < renew_period
    }
}

/// returns number of days until the first certificate in the chain
/// expires and whether any certificate is from STAGING
pub fn analyze(combined: &Signed) -> eyre::Result<CertInfo> {
    use x509_parser::prelude::*;

    let mut staging = false;
    let mut expires_in = Duration::MAX;
    let mut expires_at = u64::MAX;

    for pem in Pem::iter_from_buffer(combined.public_cert_chain.as_bytes()) {
        let pem = pem.expect("Reading next PEM block failed");
        let x509 = pem.parse_x509().expect("X.509: decoding DER failed");

        staging |= x509
            .issuer()
            .iter_organization()
            .map(|o| o.as_str().unwrap())
            .any(|s| s.contains("STAGING"));
        expires_in = expires_in.min(
            x509.validity()
                .time_to_expiration()
                .unwrap_or(Duration::ZERO),
        );
        expires_at = expires_at.min(
            x509.validity()
                .not_after
                .timestamp()
                .try_into()
                .expect("got negative timestamp from x509 certificate, this is a bug"),
        )
    }

    Ok(CertInfo {
        staging,
        expires_in,
        seed: expires_at,
    })
}
