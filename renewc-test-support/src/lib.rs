use std::io::Write;

use color_eyre::eyre;
use renewc::cert::format::PemItem;
use renewc::cert::Signed;
use time::OffsetDateTime;

use self::gen_cert::generate_cert_with_chain;

pub mod gen_cert;
pub mod port_binder;

pub struct TestAcme {
    cert_expires: OffsetDateTime,
}

impl TestAcme {
    pub fn new(cert_expires: OffsetDateTime) -> Self {
        Self { cert_expires }
    }
}

impl renewc::ACME for TestAcme {
    async fn renew<P: PemItem, W: Write + Send>(
        &self,
        config: &renewc::Config,
        stdout: &mut W,
        _debug: bool,
    ) -> eyre::Result<Signed<P>> {
        writeln!(stdout, "generating certificate").expect("printing should not fail");
        let combined =
            generate_cert_with_chain(self.cert_expires, !config.production, &config.domains);
        writeln!(stdout, "TestAcme, not signing certificate").expect("printing should not fail");
        Ok(combined)
    }
}

pub struct TestPrinter;

impl Write for TestPrinter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let string = String::from_utf8_lossy(buf);
        print!("{string}");
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn setup_color_eyre() {
    use std::sync::Once;
    static COLOR_EYRE_SETUP: Once = Once::new();
    COLOR_EYRE_SETUP.call_once(|| color_eyre::install().unwrap());
}

pub fn setup_tracing() {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    let filter = filter::EnvFilter::builder()
        .parse("renewc=debug,info")
        .unwrap();

    let fmt = fmt::layer()
        .pretty()
        .with_line_number(true)
        .with_test_writer();

    let _ignore_err = tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .with(ErrorLayer::default())
        .try_init();
}

#[cfg(test)]
mod tests {
    use gen_cert::valid;
    use pem::Pem;
    use renewc::{Config, ACME};
    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn acme_test_impl_pem_has_private_key() {
        let dir = tempdir().unwrap();
        let acme = TestAcme::new(valid());
        let cert: Signed<Pem> = acme
            .renew(
                &Config::test(42, &dir.path().join("test_cert")),
                &mut TestPrinter,
                true,
            )
            .await
            .unwrap();

        let private_key = String::from_utf8(cert.private_key.as_bytes()).unwrap();
        assert!(!private_key.is_empty());
        assert!(private_key.contains("END PRIVATE KEY"));
        assert!(
            private_key
                .as_str()
                .trim_start_matches("-----BEGIN PRIVATE KEY -----")
                .trim_end_matches("-----END PRIVATE KEY-----")
                .chars()
                .count()
                > 100
        );
    }
}
