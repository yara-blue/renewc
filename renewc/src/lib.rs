#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::io::Write;

use cert::format::PemItem;
use cert::info::Info as CertInfo;
use cert::Signed;
use color_eyre::eyre;

pub mod advise;
pub mod cert;
pub mod config;
pub mod diagnostics;
pub mod renew;

use advise::CheckResult;
pub use config::name;
pub use config::Config;
use owo_colors::OwoColorize;

/// during integration testing we do not want to hit lets encrypts backend
/// by passing the ACME implementation we can test other functionality.
pub trait ACME {
    #[allow(async_fn_in_trait)]
    async fn renew<P: PemItem, W: Write + Send>(
        &self,
        config: &Config,
        stdout: &mut W,
        debug: bool,
    ) -> eyre::Result<Signed<P>>;
}

pub async fn run<P: PemItem>(
    acme_impl: &mut impl ACME,
    out: &mut (impl Write + Send),
    config: &Config,
    debug: bool,
) -> eyre::Result<Option<Signed<P>>> {
    if config.force {
        let signed = acme_impl.renew(config, out, debug).await?;
        return Ok(Some(signed));
    }

    match CertInfo::from_disk(config, out) {
        Ok(Some(cert_info)) => {
            info!(out, "Existing certificate: {}", cert_filename(config));
            match advise::given_existing(config, cert_info, out) {
                CheckResult::Refuse { status, warning } => {
                    if let Some(status) = status {
                        info!(out, "{status}");
                    }
                    warn!(out, "{warning}");
                    return Ok(None);
                }
                CheckResult::Accept { status } => info!(out, "{status}"),
                CheckResult::Warn { warning } => warn!(out, "{warning}"),
            }
        }
        Ok(None) => info!(out, "No existing certificate found"),
        Err(e) => print_advice_error_chain(out, e),
    }

    if config.production {
        check_against_staging(out, config, acme_impl, debug).await?;
        info!(out, "requesting production certificate");
    } else {
        info!(out, "requesting staging certificate");
    }
    let mut stdout = IndentedOut::new(out);
    let signed = acme_impl.renew(config, &mut stdout, debug).await?;
    Ok(Some(signed))
}

async fn check_against_staging(
    out: &mut (impl Write + Send),
    config: &Config,
    acme_impl: &mut impl ACME,
    debug: bool,
) -> Result<(), eyre::Error> {
    info!(out, "checking if request can succeed using staging");
    let staging_config = Config {
        production: false,
        ..config.clone()
    };
    Ok({
        let mut stdout = IndentedOut::new(out);
        let _: Signed<pem::Pem> = acme_impl.renew(&staging_config, &mut stdout, debug).await?;
    })
}

fn print_advice_error_chain(stdout: &mut (impl Write + Send), e: eyre::Error) {
    warn!(stdout, "Warning: renew advise impossible");
    for (i, err) in e.chain().enumerate() {
        warn!(stdout, "   {i}: {err}");
    }
    writeln!(
        stdout,
        "Note: {}",
        "This might mean the previous certificate is corrupt or broken".blue()
    )
    .unwrap();
}

struct IndentedOut<'a> {
    out: &'a mut (dyn Write + Send),
    need_leading_tab: bool,
}

impl<'a> IndentedOut<'a> {
    fn new(out: &'a mut (dyn Write + Send)) -> Self {
        Self {
            out,
            need_leading_tab: true,
        }
    }
}

impl Write for IndentedOut<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let buf = String::from_utf8_lossy(buf).to_string();

        if self.need_leading_tab {
            // correct for last line end not being followed by tab
            self.out
                .write_all("\t".as_bytes())
                .expect("out should support normal log amounts of data");
        }

        // leave line ends at end alone, it might need to be followed by not indented text
        let indented = if let Some(without_last_char) = buf.strip_suffix('\n') {
            let mut without_last_char = without_last_char.replace("\n", "\n\t");
            self.need_leading_tab = true;
            without_last_char.push('\n');
            without_last_char
        } else {
            self.need_leading_tab = false;
            buf.replace("\n", "\n\t")
        };
        self.out.write_all(indented.as_bytes())?;

        // if we return from write(indented) the returned len is larger then
        // what the calling code expects which can make it crash
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

fn cert_filename(config: &Config) -> String {
    config
        .output_config
        .cert_path
        .as_path()
        .file_name()
        .expect("file name is auto generated if none was set by the user")
        .to_string_lossy()
        .to_string()
}
