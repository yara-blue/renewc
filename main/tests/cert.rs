use std::fs;
use std::path::PathBuf;

use owo_colors::OwoColorize;
use rcgen::{Certificate, CertificateParams, IsCa};
use renewc::{run, Config};
use tempfile::TempDir;
use time::OffsetDateTime;

mod shared;

fn ca_cert() -> Certificate {
    let subject_alt_names = vec!["letsencrypt.org".to_string()];
    let mut params = CertificateParams::new(subject_alt_names);
    params.not_after = year2500();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    Certificate::from_params(params).unwrap()
}

fn client_cert(valid_till: OffsetDateTime) -> Certificate {
    let subject_alt_names = vec!["example.org".to_string()];
    let mut params = CertificateParams::new(subject_alt_names);
    params.not_after = valid_till;
    Certificate::from_params(params).unwrap()
}

fn generate_cert_with_chain(valid_till: OffsetDateTime) -> String {
    let root_ca_cert = ca_cert();
    let root_ca = root_ca_cert.serialize_pem().unwrap();

    let intermediate_ca_cert = ca_cert();
    let intermediate_ca = intermediate_ca_cert
        .serialize_pem_with_signer(&root_ca_cert)
        .unwrap();

    let client_ca = client_cert(valid_till)
        .serialize_pem_with_signer(&intermediate_ca_cert)
        .unwrap();

    let mut chain = client_ca;
    chain.push_str(&intermediate_ca);
    chain.push_str(&root_ca);
    chain
}

fn write_cert(dir: &TempDir, cert: String) -> PathBuf {
    let path = dir.path().join("cert.pem");
    fs::write(&path, cert).unwrap();
    path
}

fn year2500() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(16_734_790_789).unwrap()
}

#[tokio::test]
async fn still_valid() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let dir = tempfile::tempdir().unwrap();

    let valid_till = year2500();
    let cert = generate_cert_with_chain(valid_till);
    let path = write_cert(&dir, cert);

    let mut config = Config::test(42);
    config.path = path;
    config.production = true;

    let mut output = Vec::new();
    run(&mut output, config, true).await.unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = format!("{}", "Production cert not yet due for renewal".green());
    let correct_start = &text[..text.len() - 5]; // remove color end char
    assert!(output.starts_with(correct_start), "stdout was: {output}");
}

#[tokio::test]
async fn dont_overwrite_production() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let dir = tempfile::tempdir().unwrap();

    let valid_till = year2500();
    let cert = generate_cert_with_chain(valid_till);
    let path = write_cert(&dir, cert);

    let mut config = Config::test(42);
    config.path = path;
    config.production = false;

    let mut output = Vec::new();
    run(&mut output, config, true).await.unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = format!("{}", "Found still valid production cert".green());
    let start = &text[..text.len() - 5]; // remove color end char
    assert!(output.starts_with(start), "stdout was: {output}");

    let text = format!(
        "{}",
        "Need user confirmation however no user input possible".red()
    );
    let end = &text[5..]; // remove color start char
    assert!(output.trim_end().ends_with(end), "stdout was: {output:?}");
}

#[tokio::test]
async fn detect_renew_expired() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let dir = tempfile::tempdir().unwrap();

    let valid_till = OffsetDateTime::now_utc();
    let cert = generate_cert_with_chain(valid_till);
    let path = write_cert(&dir, cert);

    let mut config = Config::test(42);
    config.path = path;
    config.production = false;

    let mut output = Vec::new();
    let _ = run(&mut output, config, true).await.unwrap_err();

    let output = String::from_utf8(output).unwrap();
    let text = format!(
        "{}",
        "Requesting Staging cert. Overwriting expired production certificate. Certificate will not be valid".red()
    );
    let start = &text[..text.len() - 5]; // remove color end char
    assert!(output.starts_with(start), "stdout was: {output}");
}
