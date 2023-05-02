use color_eyre::eyre::{self, bail};
use format::{Label, PemItem};

pub mod format;
pub mod info;
pub mod io;
pub mod load;
pub mod store;

#[derive(Debug)]
pub struct MaybeSigned<P: PemItem> {
    // PEM encoded
    pub(crate) certificate: P,
    // PEM encoded
    pub(crate) private_key: Option<P>,
    // PEM encoded
    pub(crate) chain: Vec<P>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed<P: PemItem> {
    // PEM encoded
    pub certificate: P,
    // PEM encoded
    pub private_key: P,
    // List of PEM encoded
    pub chain: Vec<P>,
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
    /// last certificate in full chain must be the domains certificate
    pub fn from_key_and_fullchain(
        private_key: String,
        mut full_chain: String,
    ) -> eyre::Result<Self> {
        let start_cert = full_chain
            .rfind(Label::Certificate.footer())
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

impl<P: PemItem> MaybeSigned<P> {
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

        let chain = P::chain_from_bytes(pem.into_bytes())?;

        Ok(MaybeSigned {
            certificate,
            private_key,
            chain,
        })
    }
}
