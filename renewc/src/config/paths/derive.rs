use color_eyre::eyre::{self, OptionExt};
use color_eyre::Section;
use itertools::Itertools;
use std::path::{Path, PathBuf};
use tracing::instrument;

/// ty is one of "", "_cert", "_key", "_chain"
#[instrument(level = "debug", ret)]
pub(crate) fn derive_path(cert_path: &Path, name: &str, ty: &str, extension: &str) -> PathBuf {
    dir(cert_path)
        .join(format!("{name}{ty}")) // ty is sometimes optional
        .with_extension(extension)
}

fn second_level_domain(full_domain: &str) -> eyre::Result<&str> {
    let last_dot = full_domain
        .rfind('.')
        .ok_or_eyre("domain has no top level domain [org/net/com etc]")
        .with_note(|| format!("domain: {}", full_domain))?;
    let (without_top_level, _top_level) = full_domain.split_at(last_dot);
    if let Some(last_dot) = without_top_level.rfind('.') {
        let (_subdomains, second_level) = without_top_level.split_at(last_dot + 1);
        Ok(second_level)
    } else {
        Ok(without_top_level)
    }
}

pub fn name(domains: &[impl AsRef<str>]) -> eyre::Result<String> {
    let mut name_parts = domains
        .iter()
        .map(AsRef::as_ref)
        .map(second_level_domain)
        .collect::<Result<Vec<_>, _>>()?;
    name_parts.sort_unstable();
    name_parts.dedup();

    Ok(name_parts.into_iter().join("+"))
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

        assert_eq!(name(&domains).unwrap(), "example+nm");
    }
}
