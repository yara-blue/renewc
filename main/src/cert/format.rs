use color_eyre::eyre::{self, bail};
use data_encoding::BASE64;

/// a single pem encoded item. Has one header and footer at
/// the start and end respectively
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemItem {
    content: String,
    label: Label,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Label {
    Certificate,
    PrivateKey,
}

impl Label {
    pub(crate) fn header(&self) -> &'static str {
        match self {
            Label::Certificate => "-----BEGIN CERTIFICATE-----\r\n",
            Label::PrivateKey => "-----BEGIN PRIVATE KEY-----\r\n",
        }
    }

    pub(crate) fn footer(&self) -> &'static str {
        match self {
            Label::Certificate => "\r\n-----END CERTIFICATE-----\r\n",
            Label::PrivateKey => "\r\n-----END PRIVATE KEY-----\r\n",
        }
    }
}

impl PemItem {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.content.as_bytes()
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.content.into_bytes()
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.content.as_str()
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

        Ok(Self {
            content: pem,
            label,
        })
    }

    #[must_use]
    fn from_der(der: Der, label: Label) -> PemItem {
        use itertools::Itertools;

        const PEM_LINE_WIDTH: usize = 64;
        let base64 = BASE64.encode(&der.into_bytes());
        let base64_lines: Vec<u8> =
            Itertools::intersperse(base64.as_bytes().chunks(PEM_LINE_WIDTH), "\r\n".as_bytes())
                .flatten()
                .copied()
                .collect();
        let base64_lines = String::from_utf8(base64_lines).unwrap();
        PemItem {
            content: label.header().to_owned() + &base64_lines + label.footer(),
            label,
        }
    }

    #[must_use]
    pub(super) fn der(&self) -> Der {
        let base64_lines = self
            .content
            .strip_prefix(self.label.header())
            .expect("content should contain header")
            .strip_suffix(self.label.footer())
            .expect("content should contain footer");

        let base64: Vec<u8> = base64_lines
            .lines()
            .flat_map(str::as_bytes)
            .copied()
            .collect();

        let binary = BASE64
            .decode(&base64)
            .expect("pemitem content should be base64 encoded");
        Der::from_bytes(binary)
    }

    pub(super) fn chain_from_bytes(bytes: Vec<u8>) -> eyre::Result<Vec<Self>> {
        let pem = String::from_utf8(bytes)?;
        Self::chain(pem)
    }

    pub(super) fn chain(mut pem: String) -> eyre::Result<Vec<Self>> {
        let mut chain = Vec::new();
        dbg!(&pem);
        while let Some(begin_cert) = pem.rfind("-----BEGIN CERTIFICATE-----") {
            let cert = pem.split_off(begin_cert);
            let cert = PemItem::from_pem(cert, Label::Certificate)?;

            chain.push(cert);
        }

        Ok(chain)
    }
}

#[derive(Debug, Clone)]
pub(super) struct Der(Vec<u8>);

impl Der {
    /// bytes must  be valid der
    #[must_use]
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }

    #[must_use]
    pub fn to_pem(self, label: Label) -> PemItem {
        PemItem::from_der(self, label)
    }

    #[must_use]
    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_invalid_pem() {
        let one_dash_too_much = "------BEGIN CERTIFICATE------\n23io4e23o4ien324oien23423ioein4n234m234mei23en23emi334h32y3e\n------END CERTIFICATE------";
        let missing_begin = "-----CERTIFICATE-----\n12oien23ie4n23you4n23h4oyu23l4en2348u7l234n23ein4o23n42h3yu4l23y432el4uy23l4e\n-----END CERTIFICATE-----";
        let missing_linefeeds = "-----CERTIFICATE-----12oien23ie4n23you4n23h4oyu23l4en2348u7l234n23ein4o23n42h3yu4l23y432el4uy23l4e-----END CERTIFICATE-----";

        for invalid in [one_dash_too_much, missing_begin, missing_linefeeds] {
            let _ = PemItem::from_pem(invalid.to_owned(), Label::Certificate).unwrap_err();
        }
    }

    #[test]
    fn reversible() {
        const ROOT_CA: &[u8] = "-----BEGIN CERTIFICATE-----\r\nMIIBkDCCATagAwIBAgIIHXJD3lzIXyMwCgYIKoZIzj0EAwIwITEfMB0GA1UEAwwW\r\ncmNnZW4gc2VsZiBzaWduZWQgY2VydDAgFw03NTAxMDEwMDAwMDBaGA8yNTAwMDQy\r\nMTE2NTk0OVowITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDBZMBMG\r\nByqGSM49AgEGCCqGSM49AwEHA0IABHtP92/H2wTvW/xZ9iSiCMnWOfaydoSWEGFi\r\nWPHBvTO0FyLEUxQKOOrunv071KrBbYECyX00Q5efWj46brjzjJajVjBUMCIGA1Ud\r\nEQQbMBmCF1NUQUdJTkcubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBQjX8hc3kNy\r\nHXuj5yHSZipVhCHtQDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUC\r\nIQD7CpgwpL6KT3Ljedh5bL4x3LSY5guONLcWIfz2X9E8ngIgbrcaTmaryZfiYnnK\r\nETaDo04pY2cDOIsIy2ycUTJL084=\r\n-----END CERTIFICATE-----\r\n".as_bytes();

        let der = PemItem::from_bytes(ROOT_CA.to_vec(), Label::Certificate)
            .unwrap()
            .der();
        assert_ne!(der.clone().into_bytes(), ROOT_CA);
        let pem = der.to_pem(Label::Certificate);
        assert_eq!(pem.as_bytes(), ROOT_CA);
    }

    #[test]
    fn parse_chain() {

    }
}
