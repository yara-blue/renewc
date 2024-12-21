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

fn warn(stdout: &mut impl Write, s: &str) {
    let s = s.red().to_string() + "\n";
    stdout.write_all(s.as_bytes()).unwrap();
}

fn info(stdout: &mut impl Write, s: &str) {
    let s = s.green().to_string() + "\n";
    stdout.write_all(s.as_bytes()).unwrap();
}

pub async fn run<P: PemItem>(
    acme_impl: &mut impl ACME,
    stdout: &mut (impl Write + Send),
    config: &Config,
    debug: bool,
) -> eyre::Result<Option<Signed<P>>> {
    if config.force {
        let signed = acme_impl.renew(config, stdout, debug).await?;
        return Ok(Some(signed));
    }

    match CertInfo::from_disk(config, stdout)
        .map(|cert| advise::given_existing(config, &cert, stdout))
    {
        Ok(CheckResult::Refuse {
            status: Some(status),
            warning,
        }) => {
            info(stdout, &status);
            warn(stdout, warning);
            return Ok(None);
        }
        Ok(CheckResult::Refuse {
            status: None,
            warning,
        }) => {
            warn(stdout, warning);
            return Ok(None);
        }
        Ok(CheckResult::Accept { status }) => {
            info(stdout, &status);
        }
        Ok(CheckResult::NoCert) => (),
        Ok(CheckResult::Warn { warning }) => warn(stdout, warning),
        Err(e) => {
            writeln!(stdout, "Warning: renew advise impossible").unwrap();
            for (i, err) in e.chain().enumerate() {
                advise::warn!(stdout, "   {i}: {err}");
            }
            writeln!(
                stdout,
                "Note: {}",
                "This might mean the previous certificate is corrupt or broken".blue()
            )
            .unwrap();
        }
    }

    let staging_config = Config {
        production: false,
        ..config.clone()
    };
    if config.production {
        info(stdout, "checking if request can succeed using staging");
        let mut stdout = IndentedOut::new(stdout);
        let _: Signed<P> = acme_impl.renew(&staging_config, &mut stdout, debug).await?;
    }
    info(stdout, "requesting production certificate");
    let mut stdout = IndentedOut::new(stdout);
    let signed = acme_impl.renew(config, &mut stdout, debug).await?;
    Ok(Some(signed))
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

impl<'a> Write for IndentedOut<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let buf = String::from_utf8_lossy(buf).to_string();

        if self.need_leading_tab {
            // correct for last line end not being followed by tab
            self.out
                .write("\t".as_bytes())
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
        self.out.write(indented.as_bytes())?;

        // if we return from write(indented) the returned len is larger then
        // what the calling code expects which can make it crash
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}
