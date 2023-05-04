use owo_colors::OwoColorize;
use pem::Pem;
use renewc::cert;
use renewc::config::Output;
use renewc::{run, Config};

mod shared;
use shared::gen_cert;
use shared::TestAcme;

#[tokio::test]
async fn production_does_not_overwrite_valid_production() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let mut acme = TestAcme::new(gen_cert::valid());
    let dir = tempfile::tempdir().unwrap();

    let mut config = Config::test(42);
    config.output.certificate_path = dir.path().join("cert.pem");
    config.output.output = Output::Pem;
    config.production = true;

    // run to place still valid cert
    let mut stdout = std::io::stdout();
    let certs = run::<Pem>(&mut acme, &mut stdout, &config, true)
        .await
        .unwrap()
        .unwrap();
    cert::store::on_disk(&config, certs).unwrap();

    // second run encounters the still valid cert and errors out
    config.production = true;
    let mut output = Vec::new();
    run::<Pem>(&mut acme, &mut output, &config, true)
        .await
        .unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = format!("{}", "Production cert not yet due for renewal".green());
    let start = &text[..text.len() - 5]; // remove color end char
    assert!(
        output.starts_with(start),
        "stdout did not start with:\n\t{start:#?}\ninstead it was:\n\t{output:#?}"
    );
}

#[tokio::test]
async fn staging_does_not_overwrite_production() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let mut acme = TestAcme::new(gen_cert::valid());
    let dir = tempfile::tempdir().unwrap();

    let mut config = Config::test(42);
    config.output.certificate_path = dir.path().join("cert.pem");
    config.output.output = Output::Pem;
    config.production = true;

    // run to place still valid cert
    let mut stdout = std::io::stdout();
    let certs = run::<Pem>(&mut acme, &mut stdout, &config, true)
        .await
        .unwrap()
        .unwrap();
    cert::store::on_disk(&config, certs).unwrap();

    // second run encounters the still valid cert and errors out
    config.production = false;
    let mut output = Vec::new();
    run::<Pem>(&mut acme, &mut output, &config, true)
        .await
        .unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = format!("{}", "Found still valid production cert".green());
    let start = &text[..text.len() - 5]; // remove color end char
    assert!(
        output.starts_with(start),
        "stdout did not start with:\n\t{text:#?}\ninstead it was:\n\t{output:#?}"
    );

    let text = format!(
        "{}",
        "Need user confirmation however no user input possible".bright_red()
    );
    let end = &text[5..]; // remove color start char
    println!("{output}");
    assert!(
        output.contains(end),
        "stdout did not contain:\n\t{end:#?}\ninstead it was:\n\t{output:#?}"
    )
}

#[tokio::test]
async fn staging_overwrites_expired_production() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let dir = tempfile::tempdir().unwrap();
    let mut acme = TestAcme::new(gen_cert::expired());

    let mut config = Config::test(42);
    config.output.certificate_path = dir.path().join("cert.pem");
    config.output.output = Output::Pem;
    config.production = true;

    // run to place still valid cert
    let mut stdout = std::io::stdout();
    let certs = run::<Pem>(&mut acme, &mut stdout, &config, true)
        .await
        .unwrap()
        .unwrap();
    cert::store::on_disk(&config, certs).unwrap();

    let mut acme = TestAcme::new(gen_cert::valid());
    config.production = false;
    let mut output = Vec::new();
    let _cert = run::<Pem>(&mut acme, &mut output, &config, true)
        .await
        .unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = format!(
        "{}",
        "Requesting staging cert. Overwriting expired production certificate. Certificate will not be valid".green()
    );
    let start = &text[..text.len() - 5]; // remove color end char
    assert!(
        output.starts_with(start),
        "stdout did not start with:\n\t{start:#?}\ninstead it was:\n\t{output:#?}"
    );
}

#[tokio::test]
async fn corrupt_existing_does_not_crash() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let dir = tempfile::tempdir().unwrap();

    let mut config = Config::test(42);
    config.output.certificate_path = dir.path().join("cert.pem");
    config.output.output = Output::Pem;
    config.production = true;

    let corrupt_data = "-----BEGIN CERTIFisrtens-----\r\n 128972184ienst\r\n-----END";
    std::fs::write(&config.output.certificate_path, corrupt_data).unwrap();

    let mut acme = TestAcme::new(gen_cert::valid());
    config.production = false;
    let mut output = Vec::new();
    let _cert = run::<Pem>(&mut acme, &mut output, &config, true)
        .await
        .unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = "Warning: renew advise impossible";
    assert!(
        output.starts_with(text),
        "stdout did not start with:\n\t{text:#?}\ninstead it was:\n\t{output:#?}"
    );
}
