use color_eyre::eyre::{self, bail, Context};
use format::{Label, PemItem};

pub mod format;
pub mod info;
pub mod io;
pub mod load;
pub mod store;

pub struct MaybeSigned<P: PemItem> {
    // PEM encoded
    pub(crate) certificate: P,
    // PEM encoded
    pub(crate) private_key: Option<P>,
    // PEM encoded
    pub(crate) chain: Vec<P>,
}

impl<P: PemItem> std::fmt::Debug for MaybeSigned<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaybeSigned")
            .field("certificate", &"hidden to prevent security leaks")
            .field(
                "private_key",
                &self
                    .private_key
                    .as_ref()
                    .map(|_| "hidden to prevent security leaks"),
            )
            .field(
                "chain",
                &self
                    .chain
                    .iter()
                    .map(|p| p.as_bytes())
                    .map(String::from_utf8)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Signed<P: PemItem> {
    // PEM encoded
    pub certificate: P,
    // PEM encoded
    pub private_key: P,
    // List of PEM encoded
    pub chain: Vec<P>,
}

impl<P: PemItem> std::fmt::Debug for Signed<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signed")
            .field("certificate", &"hidden to prevent security leaks")
            .field("private_key", &"hidden to prevent security leaks")
            .field(
                "chain",
                &self
                    .chain
                    .iter()
                    .map(|p| p.as_bytes())
                    .map(String::from_utf8)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl<P: PemItem> TryFrom<MaybeSigned<P>> for Signed<P> {
    type Error = eyre::Report;

    fn try_from(signed: MaybeSigned<P>) -> Result<Self, Self::Error> {
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

impl<P: PemItem> Signed<P> {
    /// first certificate in full chain must be the domains certificate
    pub fn from_key_and_fullchain(
        private_key: String,
        mut full_chain: String,
    ) -> eyre::Result<Self> {
        let mut certs = Vec::new();
        while let Some(begin_cert) = full_chain.rfind("-----BEGIN CERTIFICATE-----") {
            certs.push(
                PemItem::from_pem(full_chain.split_off(begin_cert), Label::Certificate)
                    .wrap_err("failed to extract chain certificates")?,
            );
        }

        let signed = certs
            .pop() // removes first element (list is reversed)
            .ok_or_else(|| eyre::eyre!("no certificates in full chain"))?;
        let chain = {
            certs.reverse();
            certs
        };

        if chain.is_empty() {
            bail!("No chain certificates in full chain")
        }

        let private_key = PemItem::from_pem(private_key, Label::PrivateKey)
            .wrap_err("failed to extract private key")?;

        Ok(Self {
            certificate: signed,
            private_key,
            chain,
        })
    }
}

impl<P> MaybeSigned<P>
where
    P: PemItem,
{
    /// expects the signed certificate to be the first certificate
    /// item (see certificate list in
    /// [rfc4346 section 7.4.2](https://www.rfc-editor.org/rfc/rfc4346#section-7.4.2)
    pub(super) fn from_pem(bytes: Vec<u8>) -> eyre::Result<Self> {
        let mut pem = String::from_utf8(bytes)?;
        let start_key = pem.rfind("-----BEGIN PRIVATE KEY-----");
        let private_key = start_key
            .map(|i| pem.split_off(i))
            .map(|p| PemItem::from_pem(p, Label::PrivateKey))
            .transpose()
            .wrap_err("failed to extract private key")?;

        const DELIMITER: &str = "-----END CERTIFICATE-----";
        let post_signed_cert = pem.find(DELIMITER).map(|i| i + DELIMITER.len());
        let chain = post_signed_cert
            .map(|i| pem.split_off(i))
            .ok_or(eyre::eyre!(
                "Can not find a certificate label in the pem content"
            ))?;
        let chain = P::chain_from_pem(chain.into_bytes()).wrap_err("failed to extract chain")?;

        // only signed cert left in pem after we split off key and chain
        let certificate = PemItem::from_pem(pem, Label::Certificate)
            .wrap_err("failed to extract signed certificate")?;

        Ok(MaybeSigned {
            certificate,
            private_key,
            chain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acme_output_to_signed() {
        let signed_cert = "-----BEGIN CERTIFICATE-----\r
BQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRfouS0E6yLB+fT3eNI3x8V9B81\r
-----END CERTIFICATE-----\r\n";
        let chain0 = "-----BEGIN CERTIFICATE-----\r
BQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRfouS0E6yLB+fT3eNI3x8V9B82\r
-----END CERTIFICATE-----\r\n";
        let chain1 = "-----BEGIN CERTIFICATE-----\r
BQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRfouS0E6yLB+fT3eNI3x8V9B83\r
-----END CERTIFICATE-----\r\n";
        let chain2 = "-----BEGIN CERTIFICATE-----\r
BQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRfouS0E6yLB+fT3eNI3x8V9B84\r
-----END CERTIFICATE-----\r\n";

        // in a single file the certificate is always before the
        // full chain
        let certs = format!("{signed_cert}\r\n{chain0}\r\n{chain1}\r\n{chain2}");

        let key = "
-----BEGIN PRIVATE KEY----- 
BQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRfouS0E6yLB+fT3eNI3x8V9B81
-----END PRIVATE KEY-----
            "
        .to_string();

        Signed::<pem::Pem>::from_key_and_fullchain(key, certs.clone()).unwrap();
        let res = MaybeSigned::<pem::Pem>::from_pem(certs.into_bytes()).unwrap();
        assert_eq!(res.certificate.to_string(), signed_cert);
        let mut chain = res.chain.into_iter().map(|p| p.to_string());
        assert_eq!(chain.next().unwrap(), chain0);
        assert_eq!(chain.next().unwrap(), chain1);
        assert_eq!(chain.next().unwrap(), chain2);
    }
}
