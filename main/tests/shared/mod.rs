use color_eyre::eyre;
use renewc::cert::Signed;

use self::gen_cert::{generate_cert_with_chain, year2500};

pub mod gen_cert;
pub mod port_binder;

pub struct TestAcme {}

#[async_trait::async_trait]
impl renewc::ACME for TestAcme {
    async fn renew(&self, config: &renewc::Config, _debug: bool) -> eyre::Result<Signed> {
        let combined = generate_cert_with_chain(year2500(), !config.production);
        Ok(combined)
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
    use renewc::{Config, ACME};

    use super::*;

    #[tokio::test]
    async fn acme_test_impl_pem_has_private_key() {
        let cert = TestAcme {}.renew(&Config::test(42), true).await.unwrap();

        dbg!(&cert.private_key);
        assert!(!cert.private_key.is_empty());
        assert!(cert.private_key.contains("END PRIVATE KEY"));
        assert!(
            cert.private_key
                .trim_start_matches("-----BEGIN PRIVATE KEY -----")
                .trim_end_matches("-----END PRIVATE KEY-----")
                .chars()
                .count()
                > 100
        );
    }
}
