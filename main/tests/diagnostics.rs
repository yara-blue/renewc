use std::sync::Once;

use renew_certs::{run, Config};

mod shared;

fn setup_color_eyre() {
    static COLOR_EYRE_SETUP: Once = Once::new();
    COLOR_EYRE_SETUP.call_once(|| color_eyre::install().unwrap())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn haproxy_binds_port() {
    setup_color_eyre();
    shared::setup_tracing();

    let (_handle, bound_port) = shared::spawn_fake_haproxy();

    use tempfile::tempdir;
    let dir = tempdir().unwrap();
    let path = dir.path().join("haproxy.cfg");

    let ha_config = include_str!("haproxy.cfg");
    let ha_config = ha_config.replace("<PORT>", &bound_port.to_string());
    std::fs::write(&path, ha_config).unwrap();

    let mut config = Config::test(bound_port);
    config.diagnostics.haproxy.path = path;

    let err = run(config, true).await.unwrap_err();
    let test = format!("{err:?}");
    assert!(test.contains("haproxy is forwarding port"));
}

#[tokio::test]
async fn insufficent_permissions() {
    setup_color_eyre();
    shared::setup_tracing();

    let config = Config::test(42);

    let err = run(config, true).await.unwrap_err();
    let test = format!("{err:?}");

    assert!(test.contains("You normally need sudo to attach to ports below 1025"));
    assert!(test.contains("port: 42"));
}
