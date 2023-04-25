use renewc::renew::InstantAcme;
use renewc::{run, Config};

mod shared;

#[cfg(target_os = "linux")]
#[tokio::test]
async fn haproxy_binds_port() {
    use tempfile::tempdir;

    shared::setup_color_eyre();
    shared::setup_tracing();

    let mut port_user = shared::port_binder::spawn("haproxy");
    let bound_port = port_user.port();

    let dir = tempdir().unwrap();
    let path = dir.path().join("haproxy.cfg");

    let ha_config = include_str!("haproxy.cfg");
    let ha_config = ha_config.replace("<PORT>", &bound_port.to_string());
    std::fs::write(&path, ha_config).unwrap();

    let mut config = Config::test(bound_port);
    config.diagnostics.haproxy.path = path;

    let err = run(InstantAcme{}, &mut std::io::stdout(), &config, true).await.unwrap_err();
    let test = format!("{err:?}");

    println!("{test:#?}");
    port_user.signal_done();
    assert!(
        test.contains("haproxy is forwarding port"),
        "error was: {test}"
    );
}

#[tokio::test]
async fn insufficent_permissions() {
    shared::setup_color_eyre();
    shared::setup_tracing();

    let config = Config::test(42);

    let err = run(InstantAcme{}, &mut std::io::stdout(), &config, true).await.unwrap_err();
    let test = format!("{err:?}");

    assert!(test.contains("You normally need sudo to attach to ports below 1025"));
    assert!(test.contains("port: 42"));
}
