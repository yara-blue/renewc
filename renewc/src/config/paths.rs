use color_eyre::{eyre, Help};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use tracing::warn;

use super::{Encoding, Output};

mod derive;
use derive::derive_path;
pub use derive::name;

fn push_extension(path: &Path, extension: &'static str) -> PathBuf {
    assert!(!extension.starts_with('.'));
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

pub(super) fn fix_extension(encoding: Encoding, path: &Path) -> eyre::Result<PathBuf> {
    use strum::IntoEnumIterator;

    let Some(extention) = path.extension() else {
        return Ok(path.with_extension(encoding.extension()));
    };

    let Some(extension) = extention.to_str() else {
        // non utf8 extension can be a valid path still but it is
        // unlikely (name.<non_utf>) could be a valid file path
        warn!(
            "Path contains non utf8 extension. While not a problem 
              when renewing certificates it can cause issues loading the
              certificate in another application."
        );
        return Ok(push_extension(path, encoding.extension()));
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

    Ok(push_extension(path, encoding.extension()))
}

#[derive(Debug, Clone)]
pub struct CertPath(PathBuf);

impl CertPath {
    pub fn new(output: &Output, cert_path: &Path, name: &str) -> eyre::Result<Self> {
        let encoding = Encoding::from(output);

        let content_description = if let Output::PemSingleFile = output {
            ""
        } else {
            "_cert"
        };

        Ok(CertPath(if cert_path.is_dir() {
            derive_path(cert_path, name, content_description, encoding.extension())
        } else {
            fix_extension(encoding, cert_path)?
        }))
    }
}

#[derive(Debug, Clone)]
pub struct KeyPath(PathBuf);

impl KeyPath {
    pub fn new(
        output: &Output,
        cert_path: &Path,
        chain_path: Option<PathBuf>,
        name: &str,
    ) -> eyre::Result<Self> {
        let encoding = Encoding::from(output);
        Ok(KeyPath(match chain_path {
            None => derive_path(cert_path, name, "_chain", encoding.extension()),
            Some(path) => fix_extension(encoding, &path)?,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct ChainPath(PathBuf);

impl ChainPath {
    pub fn new(
        output: &Output,
        cert_path: &Path,
        chain_path: Option<PathBuf>,
        name: &str,
    ) -> eyre::Result<Self> {
        let encoding = Encoding::from(output);
        Ok(ChainPath(match chain_path {
            None => derive_path(cert_path, name, "_key", encoding.extension()),
            Some(path) => fix_extension(encoding, &path)?,
        }))
    }
}

macro_rules! impl_path_struct {
    ($struct:ident) => {
        impl Display for $struct {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_fmt(format_args!("{}", self.0.display()))
            }
        }

        impl $struct {
            pub fn as_path(&self) -> &Path {
                &self.0
            }
        }
    };
}

impl_path_struct!(ChainPath);
impl_path_struct!(CertPath);
impl_path_struct!(KeyPath);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_extension() {
        let path = Path::new("/etc/ssl/test.test");
        assert_eq!(
            fix_extension(Encoding::PEM, path).unwrap(),
            PathBuf::from("/etc/ssl/test.test.pem")
        );

        let path = Path::new("/etc/ssl/test");
        assert_eq!(
            fix_extension(Encoding::PEM, path).unwrap(),
            PathBuf::from("/etc/ssl/test.pem")
        );

        let path = Path::new("/etc/ssl/test");
        assert_eq!(
            fix_extension(Encoding::DER, path).unwrap(),
            PathBuf::from("/etc/ssl/test.der")
        );
    }

    #[test]
    fn wrong_extension() {
        let path = Path::new("/etc/ssl/test.test.der");
        assert!(fix_extension(Encoding::PEM, path).is_err());

        let path = Path::new("/etc/ssl/test.pem");
        assert!(fix_extension(Encoding::DER, path).is_err());
    }
}
