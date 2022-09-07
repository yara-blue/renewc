use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

pub fn extract_combined(path: &Path) -> eyre::Result<Option<Signed>> {
    let combined = match fs::read_to_string(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e)
                .wrap_err("Could not read certificate")
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

/// returns number of days until the first certificate in the chain
/// expires and whether any certificate is from STAGING
pub fn analyze(combined: Signed) -> eyre::Result<(Duration, bool)> {
    use x509_parser::prelude::*;

    let mut staging = false;
    let mut expires_in = Duration::ZERO;
    for pem in Pem::iter_from_buffer(&combined.public_cert_chain.as_bytes()) {
        let pem = pem.expect("Reading next PEM block failed");
        let x509 = pem.parse_x509().expect("X.509: decoding DER failed");

        staging |= x509
            .issuer()
            .iter_organization()
            .map(|o| o.as_str().unwrap())
            .any(|s| s.contains("STAGING"));
        expires_in = expires_in.max(
            x509.validity()
                .time_to_expiration()
                .map(|dur| dur.try_into().unwrap())
                .unwrap_or(Duration::ZERO),
        )
    }

    Ok((expires_in, staging))
}
