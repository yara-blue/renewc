use pem::Pem;
use renewc::cert::{load, store, Signed};
use renewc::Config;

use renewc::config::Output;
use renewc_test_support::gen_cert;
use renewc_test_support::TestPrinter;
use time::OffsetDateTime;

#[tokio::test]
async fn der_and_pem_equal() {
    renewc_test_support::setup_color_eyre();
    renewc_test_support::setup_tracing();

    let dir = tempfile::tempdir().unwrap();

    let valid_till = OffsetDateTime::now_utc();
    let original: Signed<Pem> = gen_cert::generate_cert_with_chain(
        valid_till,
        false,
        &vec![String::from("testdomain.org")],
    );

    let mut config = Config::test(42, &dir.path());
    config.production = false;

    for format in [
        Output::PemSingleFile,
        Output::PemSeperateKey,
        Output::PemSeperateChain,
        Output::PemAllSeperate,
        Output::Der,
    ] {
        config.output_config.output = dbg!(format);
        store::on_disk(&config, original.clone(), &mut TestPrinter).unwrap();
        let loaded = load::from_disk(&config, &mut TestPrinter).unwrap().unwrap();

        assert_eq!(
            loaded, original,
            "certs stored then loaded from {format:?} are different then originally stored"
        );
    }
}
