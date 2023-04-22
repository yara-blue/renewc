pub mod port_binder;

pub fn setup_color_eyre() {
    use std::sync::Once;
    static COLOR_EYRE_SETUP: Once = Once::new();
    COLOR_EYRE_SETUP.call_once(|| color_eyre::install().unwrap())
}

pub fn setup_tracing() {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    let filter = filter::EnvFilter::builder()
        .parse("renewc=debug,info")
        .unwrap();

    let fmt = fmt::layer()
        .pretty()
        .with_line_number(true)
        .with_test_writer();

    let _ignore_err = tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .with(ErrorLayer::default())
        .try_init();
}
