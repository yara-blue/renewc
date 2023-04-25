use color_eyre::eyre;
use der::{DecodePem, EncodeValue};
use x509_cert::Certificate;

use super::Signed;

impl Signed {
    pub fn der(self) -> eyre::Result<Vec<u8>> {
        let combined = self.cert_chain + &self.private_key;
        let cert = Certificate::from_pem(dbg!(combined).as_bytes())
            .expect("ACME client should return valid PEM");
        let mut writer = Vec::new();
        cert.encode_value(&mut writer)?;
        Ok(writer)
    }
    pub fn pem(self) -> eyre::Result<Vec<u8>> {
        let combined = self.cert_chain + "\n" + &self.private_key;
        Ok(combined.as_bytes().to_vec())
    }
}
