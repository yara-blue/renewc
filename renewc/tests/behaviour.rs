use owo_colors::OwoColorize;
use pem::Pem;
use renewc::cert;
use renewc::config::Output;
use renewc::{run, Config};

use renewc_test_support::gen_cert;
use renewc_test_support::TestAcme;
use renewc_test_support::TestPrinter;
use tracing::info;

#[tokio::test]
async fn production_does_not_overwrite_valid_production() {
    renewc_test_support::setup_color_eyre();
    renewc_test_support::setup_tracing();

    let mut acme = TestAcme::new(gen_cert::valid());
    let dir = tempfile::tempdir().unwrap();

    let mut config = Config::test(42, &dir.path());
    config.output_config.output = Output::PemSingleFile;
    config.production = true;

    // run to place still valid cert
    let certs = run::<Pem>(&mut acme, &mut TestPrinter, &config, true)
        .await
        .unwrap()
        .expect("should return certificate, since none exists before it");
    cert::store::on_disk(&config, certs, &mut TestPrinter).unwrap();

    info!("test run starts now");
    // second run encounters the still valid cert and errors out
    config.production = true;
    let mut output = Vec::new();
    run::<Pem>(&mut acme, &mut output, &config, true)
        .await
        .unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = format!(
        "{}\n{}",
        "Existing certificate: testdomain.org_cert.pem".green(),
        "Production cert not yet due for renewal".green()
    );
    let start = &text[..text.len() - 5]; // remove color end char
    assert!(
        output.starts_with(start),
        "stdout did not start with:\n\t{start:#?}\ninstead it was:\n\t{output:#?}"
    );
}

#[tokio::test]
async fn staging_does_not_overwrite_production() {
    renewc_test_support::setup_color_eyre();
    renewc_test_support::setup_tracing();

    let mut acme = TestAcme::new(gen_cert::valid());
    let dir = tempfile::tempdir().unwrap();

    let mut config = Config::test(42, &dir.path().join("test_cert"));
    config.output_config.output = Output::PemSingleFile;
    config.production = true;

    // run to place still valid cert
    let certs = run::<Pem>(&mut acme, &mut TestPrinter, &config, true)
        .await
        .unwrap()
        .unwrap();
    cert::store::on_disk(&config, certs, &mut TestPrinter).unwrap();

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
    );
}

#[tokio::test]
async fn staging_overwrites_expired_production() {
    renewc_test_support::setup_color_eyre();
    renewc_test_support::setup_tracing();

    let dir = tempfile::tempdir().unwrap();
    let mut acme = TestAcme::new(gen_cert::expired());

    let mut config = Config::test(42, &dir.path().join("test_cert"));
    config.output_config.output = Output::PemSingleFile;
    config.production = true;

    // run to place expired cert
    let certs = run::<Pem>(&mut acme, &mut TestPrinter, &config, true)
        .await
        .unwrap()
        .unwrap();
    cert::store::on_disk(&config, certs, &mut TestPrinter).unwrap();

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
    renewc_test_support::setup_color_eyre();
    renewc_test_support::setup_tracing();

    let dir = tempfile::tempdir().unwrap();

    let mut config = Config::test(42, &dir.path().join("test_cert"));
    config.output_config.output = Output::PemSingleFile;
    config.production = true;

    let corrupt_data = "-----BEGIN CERTIFisrtens-----\r\n 128972184ienst\r\n-----END";
    std::fs::write(config.output_config.cert_path.as_path(), corrupt_data).unwrap();

    let mut acme = TestAcme::new(gen_cert::valid());
    config.production = false;
    let mut output = Vec::new();
    let _cert = run::<Pem>(&mut acme, &mut output, &config, true)
        .await
        .unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = "\u{1b}[33mWarning: renew advise impossible";
    assert!(
        output.starts_with(text),
        "stdout did not start with:\n\t{text:#?}\ninstead it was:\n\t{output:#?}"
    );
}

#[tokio::test]
async fn warn_about_missing_name() {
    renewc_test_support::setup_color_eyre();
    renewc_test_support::setup_tracing();

    let dir = tempfile::tempdir().unwrap();
    let mut acme = TestAcme::new(gen_cert::expired());

    let mut config = Config::test(42, &dir.path().join("test_cert"));
    config.output_config.output = Output::PemSingleFile;
    config.domains = ["example.org", "subdomain.example.org", "other.domain"]
        .into_iter()
        .map(str::to_string)
        .collect();

    // run to place expired cert
    let certs = run::<Pem>(&mut acme, &mut TestPrinter, &config, true)
        .await
        .unwrap()
        .unwrap();
    cert::store::on_disk(&config, certs, &mut TestPrinter).unwrap();

    let mut acme = TestAcme::new(gen_cert::valid());
    config.domains = vec![String::from("example.org"), String::from("other.domain")];
    let mut output = Vec::new();
    let _cert = run::<Pem>(&mut acme, &mut output, &config, true)
        .await
        .unwrap();

    let output = String::from_utf8(output).unwrap();
    let text = format!(
        "{}",
        "Certificate will not be valid for (sub)domain that is currently valid, that (sub)domain is: subdomain.example.org".green()
    );
    let start = &text[..text.len() - 5]; // remove color end char
    assert!(
        dbg!(&output).starts_with(dbg!(start)),
        "stdout did not start with:\n\t{start:#?}\ninstead it was:\n\t{output:#?}"
    );
}

#[tokio::test]
async fn run_against_staging_first() {
    renewc_test_support::setup_color_eyre();
    renewc_test_support::setup_tracing();

    let dir = tempfile::tempdir().unwrap();

    let mut acme = TestAcme::new(gen_cert::valid());

    let mut config = Config::test(42, &dir.path().join("test_cert"));
    config.output_config.output = Output::PemSingleFile;
    config.production = true;
    config.domains = vec![String::from("example.org"), String::from("other.domain")];

    let mut output = Vec::new();
    let _cert = run::<Pem>(&mut acme, &mut output, &config, true)
        .await
        .unwrap();

    let output = String::from_utf8(output).unwrap();
    let header = "\u{1b}[32mchecking if request can succeed using staging\u{1b}[39m";
    let indented = output
        .strip_prefix(header)
        .expect("header informing of staging should be the first");
    assert_eq!(
        indented,"\n\tgenerating certificate\n\tTestAcme, not signing certificate\n\u{1b}[32mrequesting production certificate\u{1b}[39m\n\tgenerating certificate\n\tTestAcme, not signing certificate\n"
    );
}
