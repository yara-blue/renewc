use core::fmt;

use color_eyre::eyre::{self, bail};

use crate::cert::MaybeSigned;

impl MaybeSigned {
    pub(super) fn from_pem(bytes: Vec<u8>) -> eyre::Result<Self> {
        let mut pem = String::from_utf8(bytes)?;
        let start_key = pem.rfind("-----BEGIN PRIVATE KEY-----");
        let private_key = start_key.map(|i| pem.split_off(i));

        let start_cert = pem.rfind("-----BEGIN CERTIFICATE-----");
        let certificate = start_cert
            .map(|i| pem.split_off(i))
            .ok_or(eyre::eyre!("Can no find a certificate"))?;

        if !certificate.ends_with("-----END CERTIFICATE-----") {
            bail!("Certificate portion of pem is incomplete")
        }

        if !private_key
            .as_ref()
            .map(|pk| pk.ends_with("-----END PRIVATE KEY-----"))
            .unwrap_or(true)
        {
            bail!("Private key portion of pem is incomplete")
        }

        let chain = chain(pem)?;

        Ok(MaybeSigned {
            certificate,
            private_key,
            chain,
        })
    }
}

pub(super) fn private_key(bytes: Vec<u8>) -> eyre::Result<Option<String>> {
    let pem = String::from_utf8(bytes)?;
    if !pem.starts_with("-----BEGIN PRIVATE KEY-----") {
        return Ok(None); // TODO: return error instead of None?
    }

    if !pem.ends_with("-----END PRIVATE KEY-----") {
        return Ok(None);
    }

    Ok(Some(pem))
}

pub(super) fn chain_from_bytes(bytes: Vec<u8>) -> eyre::Result<Vec<String>> {
    let pem = String::from_utf8(bytes)?;
    chain(pem)
}

pub(super) fn chain(mut pem: String) -> eyre::Result<Vec<String>> {
    let mut chain = Vec::new();
    while let Some(begin_cert) = pem.rfind("-----BEGIN CERTIFICATE-----") {
        let cert = pem.split_off(begin_cert);

        if !pem.starts_with("-----BEGIN CERTIFICATE-----") {
            return Ok(Vec::new());
        }

        if !pem.ends_with("-----END CERTIFICATE-----") {
            return Ok(Vec::new());
        }

        chain.push(cert);
    }

    Ok(chain)
}

pub(super) fn certificate(bytes: Vec<u8>) -> eyre::Result<Option<String>> {
    let pem = String::from_utf8(bytes)?;

    if !pem.starts_with("-----BEGIN CERTIFICATE-----") {
        return Ok(None);
    }

    if !pem.ends_with("-----END CERTIFICATE-----") {
        return Ok(None);
    }

    Ok(Some(pem))
}
