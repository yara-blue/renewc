use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use color_eyre::eyre;
use crate::config::Output;

use super::Signed;

fn key_path(cert_path: &Path) {
    // if cert_path.is_file()
}

fn from_config(config: &Output) -> eyre::Result<Option<Signed>> {
    let Output { certificate_path: cert, key_path: key, chain_path: chain, .. } = config;
    
    /// check cert path derived
    /// check hardcoded if specified
    match (key, chain) {
        (None, None) => todo!(),
        (None, Some(_)) => todo!(),
        (Some(_), None) => todo!(),
        (Some(_), Some(_)) => todo!(),
    }

    todo!()

    // match fs::read(path) {
    //     Err(e) if e.kind() == ErrorKind::NotFound => {
    //         tracing::debug!("No certificate already at {}", path.display());
    //         Ok(None)
    //     }
    //     Err(e) => Err(e)
    //         .wrap_err("Could not check for existing certificate")
    //         .suggestion("Check if the path is correct")
    //         .with_note(|| format!("path: {path:?}")),
    //     Ok(bytes) => Ok(Some(bytes)),
    // }
}
