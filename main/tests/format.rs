use pem::Pem;
use renewc::cert::{load, store, Signed};
use renewc::Config;

mod shared;
use renewc::config::Output;
use shared::gen_cert;
use shared::TestPrinter;
use time::OffsetDateTime;

#[tokio::test]
async fn der_and_pem_equal() {
    shared::setup_color_eyre();
    shared::setup_tracing();

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
        Output::Pem,
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
