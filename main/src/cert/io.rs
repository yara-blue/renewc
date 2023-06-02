use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use color_eyre::eyre::{self, Context};
use color_eyre::Help;

pub(super) fn read_any_file(path: &Path) -> eyre::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => {
            tracing::debug!("No file at {}", path.display());
            Ok(None)
        }
        Err(e) => Err(e)
            .wrap_err("Could not check for file")
            .suggestion("Check if the path is correct")
            .with_note(|| format!("path: {path:?}")),
        Ok(bytes) => Ok(Some(bytes)),
    }
}
