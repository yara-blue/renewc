use color_eyre::eyre::{self, OptionExt};
use color_eyre::Section;
use itertools::Itertools;
use std::path::{Path, PathBuf};
use tracing::instrument;

/// ty is one of "", "cert_", "key_", "chain_"
#[instrument(level = "debug", ret)]
pub(crate) fn derive_path(path: &Path, name: &str, ty: &str, extension: &str) -> PathBuf {
    let path = dir(path).join(format!("{ty}{name}")); // ty is sometimes optional
    with_added_extension(path, extension)
}

fn second_and_top_level_domain(full_domain: &str) -> eyre::Result<&str> {
    let last_dot = full_domain
        .rfind('.')
        .ok_or_eyre("domain has no top level domain [org/net/com etc]")
        .with_note(|| format!("domain: {}", full_domain))?;
    if let Some(second_last_dot) = full_domain[..last_dot].rfind('.') {
        let (_, second_and_top_level) = full_domain.split_at(second_last_dot + 1);
        Ok(second_and_top_level)
    } else {
        Ok(full_domain) // only second and top level in the domain
    }
}

#[test]
fn test_second_and_top_level_domain() {
    let inputs = ["davidsk.dev", "share.davidsk.dev", "matrix.davidsk.dev"];
    let outputs = inputs.map(second_and_top_level_domain).map(Result::unwrap);
    assert_eq!(outputs, ["davidsk.dev", "davidsk.dev", "davidsk.dev"]);
}

pub fn name(domains: &[impl AsRef<str>]) -> eyre::Result<String> {
    let mut name_parts = domains
        .iter()
        .map(AsRef::as_ref)
        .map(second_and_top_level_domain)
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

pub(crate) fn with_added_extension(path: PathBuf, extension: &str) -> PathBuf {
    assert!(!extension.starts_with('.'));
    let mut path = path.into_os_string();
    path.push(".");
    path.push(extension);
    PathBuf::from(path)
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

        assert_eq!(name(&domains).unwrap(), "example.org+nm.org");
    }
}
