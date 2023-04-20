use std::fs;

use rcgen::{Certificate, CertificateParams};
use renewc::{run, Config};
use tempfile::TempDir;
use time::{OffsetDateTime, Duration};
mod shared;

fn generate_cert(valid_till: time::OffsetDateTime) -> String {
    // Generate a certificate that's valid for "localhost" and "hello.world.example"
    let subject_alt_names = vec!["hello.world.example".to_string(), "localhost".to_string()];

    let mut params = CertificateParams::new(subject_alt_names);
    params.not_after = valid_till;
    Certificate::from_params(params)
        .unwrap()
        .serialize_private_key_pem()
}

#[tokio::test]
async fn still_valid() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let dir = TempDir::new().unwrap();
    let cert_path = dir.path().join("cert.pem");

    let valid_till = OffsetDateTime::now_utc() + Duration::days(7);
    let cert = generate_cert(valid_till);
    fs::write(&cert_path, cert).unwrap();

    let mut config = Config::test(42);
    config.path = cert_path;

    run(config, true).await.unwrap();
}
