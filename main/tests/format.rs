use renewc::cert::{load, store};
use renewc::Config;

mod shared;
use renewc::config::Output;
use shared::gen_cert;
use time::OffsetDateTime;

#[tokio::test]
async fn der_and_pem_equal() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cert.pem");

    let valid_till = OffsetDateTime::now_utc();
    let original = gen_cert::generate_cert_with_chain(valid_till, false);

    let mut config = Config::test(42);
    config.production = false;
    config.output.certificate_path = path;

    for format in [
        Output::Pem,
        Output::PemSeperateKey,
        Output::PemSeperateChain,
        Output::PemAllSeperate,
        Output::Der,
    ]
    .into_iter()
    {
        config.output.output = format.clone();
        store::on_disk(&config, original.clone()).unwrap();
        let loaded = load::from_disk(&config).unwrap().unwrap();

        assert_eq!(
            loaded, original,
            "certs stored then loaded from {format:?} are different then originally stored"
        );
    }
}
