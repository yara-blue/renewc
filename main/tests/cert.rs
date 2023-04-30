use owo_colors::OwoColorize;
use renewc::config::Output;
use renewc::{run, Config};
use time::OffsetDateTime;

mod shared;
use shared::gen_cert;
use shared::TestAcme;

#[tokio::test]
async fn production_does_not_overwrite_valid_production() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let dir = tempfile::tempdir().unwrap();

    let valid_till = gen_cert::year2500();
    let cert = gen_cert::generate_cert_with_chain(valid_till, false);
    let path = gen_cert::write_single_chain(&dir, cert);

    let mut config = Config::test(42);
    config.output.certificate_path = path;
    config.output.output = Output::Pem;
    config.production = true;

    let mut output = Vec::new();
    run(TestAcme {}, &mut output, &config, true).await.unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = format!("{}", "Production cert not yet due for renewal".green());
    let correct_start = &text[..text.len() - 5]; // remove color end char
    assert!(output.starts_with(correct_start), "stdout was: {output}");
}

#[tokio::test]
async fn staging_does_not_overwrite_production() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let dir = tempfile::tempdir().unwrap();

    let valid_till = gen_cert::year2500();
    let cert = gen_cert::generate_cert_with_chain(valid_till, false);
    let path = gen_cert::write_single_chain(&dir, cert);

    let mut config = Config::test(42);
    config.output.certificate_path = path;
    config.output.output = Output::Pem;
    config.production = false;

    let mut output = Vec::new();
    run(TestAcme {}, &mut output, &config, true).await.unwrap();

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
async fn staging_overwrites_expired_production() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let dir = tempfile::tempdir().unwrap();

    let valid_till = OffsetDateTime::now_utc();
    let cert = gen_cert::generate_cert_with_chain(valid_till, false);
    let path = gen_cert::write_single_chain(&dir, cert);

    let mut config = Config::test(42);
    config.output.certificate_path = path;
    config.output.output = Output::Pem;
    config.production = false;

    let mut output = Vec::new();
    let _cert = run(TestAcme {}, &mut output, &config, true).await.unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = format!(
        "{}",
        "Requesting Staging cert. Overwriting expired production certificate. Certificate will not be valid".red()
    );
    let start = &text[..text.len() - 5]; // remove color end char
    assert!(output.starts_with(start), "stdout was: {output}");
}
