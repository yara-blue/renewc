use color_eyre::eyre::{self, bail, Context};

use pem::Pem;

impl PemItem for Pem {
    fn into_bytes(self) -> Vec<u8> {
        pem::encode(&self).into_bytes()
    }

    fn from_pem(pem_encoded: impl AsRef<[u8]>, label: Label) -> eyre::Result<Self> {
        let pem = pem::parse(pem_encoded).wrap_err("Not valid pem")?;
        let mut headers = pem.headers().iter();
        let start = headers
            .next()
            .ok_or_else(|| eyre::eyre!("Pem must have start header"))?;
        let end = headers
            .next()
            .ok_or_else(|| eyre::eyre!("Pem must have end header"))?;

        if start.0 != "BEGIN" {
            bail!("wrong start header");
        }
        if start.1 != label.header() {
            bail!("wrong start label");
        }

        if end.0 != "END" {
            bail!("wrong end header");
        }
        if end.1 != label.footer() {
            bail!("wrond end label");
        }

        Ok(pem)
    }

    fn from_der(der: Der, label: Label) -> Self {
        Pem::new(label.header(), der.into_bytes())
    }

    fn der(self) -> Der {
        Der(self.into_contents())
    }

    fn chain_from_bytes(bytes: Vec<u8>) -> eyre::Result<Vec<Self>> {
        Ok(pem::parse_many(bytes)?)
    }
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

pub trait PemItem: Sized {
    #[must_use]
    fn into_bytes(self) -> Vec<u8>;

    fn from_pem(encoded: impl AsRef<[u8]>, label: Label) -> eyre::Result<Self>
    where
        Self: Sized;

    #[must_use]
    fn from_der(der: Der, label: Label) -> Self;

    #[must_use]
    fn der(self) -> Der;

    fn chain_from_bytes(bytes: Vec<u8>) -> eyre::Result<Vec<Self>>
    where
        Self: Sized;
}

#[derive(Debug, Clone)]
pub struct Der(Vec<u8>);

impl Der {
    /// bytes must  be valid der
    #[must_use]
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }

    #[must_use]
    pub fn to_pem<P: PemItem>(self, label: Label) -> P {
        P::from_der(self, label)
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
    fn parse_chain() {}
}
