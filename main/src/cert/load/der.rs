use color_eyre::eyre;
use der::pem::LineEnding;
use der::{Decode, EncodePem};
use x509_cert::Certificate;

use crate::cert::MaybeSigned;

impl MaybeSigned {
    pub(super) fn from_der(bytes: Vec<u8>) -> eyre::Result<Self> {
        let cert = Certificate::from_der(&bytes)?;
        let pem = cert.to_pem(LineEnding::CR)?;
        Ok(MaybeSigned {
            certificate: pem,
            private_key: None,
            chain: Vec::new(),
        })
    }
}
