use color_eyre::eyre::{self, bail};
use data_encoding::BASE64;

/// a single pem encoded item. Has one header and footer at
/// the start and end respectively
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemItem(String);

#[derive(Debug)]
pub enum Label {
    Certificate,
    PrivateKey,
}

impl Label {
    fn header(&self) -> &'static str {
        match self {
            Label::Certificate => "-----BEGIN CERTIFICATE-----\n",
            Label::PrivateKey => "-----BEGIN PRIVATE KEY-----\n",
        }
    }

    fn footer(&self) -> &'static str {
        match self {
            Label::Certificate => "\n-----END CERTIFICATE-----",
            Label::PrivateKey => "\n-----END PRIVATE KEY-----",
        }
    }
}

impl PemItem {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn from_bytes(bytes: Vec<u8>, label: Label) -> eyre::Result<Self> {
        let pem = String::from_utf8(bytes)?;
        Self::from_pem(pem, label)
    }

    pub fn from_pem(pem: String, label: Label) -> eyre::Result<Self> {
        if !pem.starts_with(label.header()) {
            bail!("pem did not start with header for: {label:?}");
        }

        if !pem.ends_with(label.footer()) {
            bail!("pem did not end with footer for: {label:?}");
        }

        Ok(Self(pem))
    }

    fn from_der(der: Der, label: Label) -> PemItem {
        PemItem(label.header().to_owned() + &der.base64() + label.footer())
    }

    pub(super) fn der(&self) -> Vec<u8> {
        let mut lines = self.0.lines();
        let base64 = lines.nth(1).unwrap();
        base64.as_bytes().to_vec()
    }

    pub(super) fn chain_from_bytes(bytes: Vec<u8>) -> eyre::Result<Vec<Self>> {
        let pem = String::from_utf8(bytes)?;
        Self::chain(pem)
    }

    pub(super) fn chain(mut pem: String) -> eyre::Result<Vec<Self>> {
        let mut chain = Vec::new();
        while let Some(begin_cert) = pem.rfind("-----BEGIN CERTIFICATE-----") {
            let cert = pem.split_off(begin_cert);
            let cert = PemItem::from_pem(cert, Label::Certificate)?;

            chain.push(cert);
        }

        Ok(chain)
    }
}

pub(super) struct Der(Vec<u8>);

impl From<PemItem> for Der {
    fn from(pem: PemItem) -> Self {
        let base64 = pem.der();
        let bytes = BASE64.decode(&base64).expect("we control PemItem");
        Der(bytes)
    }
}

impl Der {
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn to_pem(self, label: Label) -> PemItem {
        PemItem::from_der(self, label)
    }

    fn base64(&self) -> String {
        BASE64.encode(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_invalid_pem() {
        let input = todo!();
    }

    #[test]
    fn reversible() {
        let input = todo!();
        
    }
}
