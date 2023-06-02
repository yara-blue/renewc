use color_eyre::{eyre, Help};
use std::path::{Path, PathBuf};
use tracing::{instrument, warn};

use super::{Encoding, Output};

fn push_extension(path: &Path, extension: &'static str) -> PathBuf {
    assert!(!extension.starts_with("."));
    let curr = path
        .extension()
        .expect("should only be called on files with an extension");
    let new = {
        let mut curr = curr.to_os_string();
        curr.push(".");
        curr.push(extension);
        curr
    };
    path.with_extension(new)
}

pub(super) fn fix_extension(encoding: &Encoding, path: &Path) -> eyre::Result<PathBuf> {
    use strum::IntoEnumIterator;

    let Some(extention) = path.extension() else {
        return Ok(path.with_extension(encoding.extension()))
    };

    let Some(extension) = extention.to_str() else {
        // non utf8 extension can be a valid path still but it is
        // unlikely (name.<non_utf>) could be a valid file path
        warn!("Path contains non utf8 extension. While not a problem 
              when renewing certificates it can cause issues loading the
              certificate in another application.");
        return Ok(push_extension(path, encoding.extension()))
    };

    if extention == encoding.extension() {
        return Ok(path.to_path_buf());
    }

    for wrong in Encoding::iter().map(Encoding::extension) {
        if extension == wrong {
            return Err(eyre::eyre!("File path has wrong extension"))
                .with_note(|| format!("extension is: \"{extension}\""))
                .with_note(|| format!("only valid extension is {}", encoding.extension()))
                .suggestion(
                    "Leave out the extension, the correct extension will be added for you",
                );
        }
    }

    return Ok(push_extension(path, encoding.extension()));
}

#[derive(Debug, Clone)]
pub struct CertPath(PathBuf);

impl CertPath {
    pub fn as_path(&self) -> &Path {
        &self.0
    }
    pub fn new(output: &Output, cert_path: &Path, name: &str) -> eyre::Result<Self> {
        let encoding = Encoding::from(output);

        Ok(CertPath(if cert_path.is_dir() {
            derive_path(cert_path, name, "cert", encoding.extension())
        } else {
            fix_extension(&encoding, cert_path)?
        }))
    }
}

#[derive(Debug, Clone)]
pub struct KeyPath(PathBuf);

impl KeyPath {
    pub fn as_path(&self) -> &Path {
        &self.0
    }
    pub fn new(
        output: &Output,
        cert_path: &Path,
        chain_path: Option<PathBuf>,
        name: &str,
    ) -> eyre::Result<Self> {
        let encoding = Encoding::from(output);
        Ok(KeyPath(match chain_path {
            None => derive_path(
                cert_path,
                name,
                "chain",
                encoding.extension(),
            ),
            Some(path) => fix_extension(&encoding, &path)?,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct ChainPath(PathBuf);

impl ChainPath {
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn new(
        output: &Output,
        cert_path: &Path,
        chain_path: Option<PathBuf>,
        name: &str,
) -> eyre::Result<Self> {
        let encoding = Encoding::from(output);
        Ok(ChainPath(match chain_path {
            None => derive_path(
                cert_path,
                name,
                "key",
                encoding.extension(),
            ),
            Some(path) => fix_extension(&encoding, &path)?,
        }))
    }
}

#[instrument(level = "debug", ret)]
pub(crate) fn derive_path(cert_path: &Path, name: &str, ty: &str, extension: &str) -> PathBuf {
    let mut path = dir(cert_path);
    path.set_file_name(format!("{name}_{ty}"));
    path.set_extension(extension);
    path
}

pub(super) fn name(domains: &[impl AsRef<str>]) -> eyre::Result<String> {
    let shortest = domains
        .iter()
        .map(AsRef::as_ref)
        .min_by_key(|d| d.len())
        .unwrap();
    let last_dot = shortest
        .rfind('.')
        .ok_or_else(|| eyre::eyre!("shortest domain has no top level domain [org/net/com etc]"))?;
    let (name, _extension) = shortest.split_at(last_dot);
    if let Some(last_dot) = name.rfind('.') {
        let (_subdomains, name) = name.split_at(last_dot + 1);
        Ok(name.to_string())
    } else {
        Ok(name.to_string())
    }
}

pub(super) fn dir(cert_path: &Path) -> PathBuf {
    let dir = if cert_path.is_file() {
        cert_path
            .parent()
            .expect("is never none if parent was a file")
    } else {
        cert_path
    };

    dir.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_extension() {
        let path = Path::new("/etc/ssl/test.test");
        assert_eq!(
            fix_extension(&Encoding::PEM, &path).unwrap(),
            PathBuf::from("/etc/ssl/test.test.pem")
        );

        let path = Path::new("/etc/ssl/test");
        assert_eq!(
            fix_extension(&Encoding::PEM, &path).unwrap(),
            PathBuf::from("/etc/ssl/test.pem")
        );

        let path = Path::new("/etc/ssl/test");
        assert_eq!(
            fix_extension(&Encoding::DER, &path).unwrap(),
            PathBuf::from("/etc/ssl/test.der")
        );
    }

    #[test]
    fn wrong_extension() {
        let path = Path::new("/etc/ssl/test.test.der");
        assert!(fix_extension(&Encoding::PEM, &path).is_err());

        let path = Path::new("/etc/ssl/test.pem");
        assert!(fix_extension(&Encoding::DER, &path).is_err());
    }
}

#[cfg(test)]
mod tests2 {
    use super::*;

    #[test]
    fn extract_name() {
        let domains = [
            "example.org",
            "subdomain.example.org",
            "subsubdomain.subdomain.example.org",
            "another.example.org",
            "even_more.example.org",
            "a.nm.org",
            "subdomain.nm.org",
        ];

        assert_eq!(name(&domains).unwrap(), "nm");
    }
}
