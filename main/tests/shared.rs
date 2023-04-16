use std::net::TcpListener;
use std::thread::{JoinHandle, self};


#[cfg(target_os = "linux")]
fn set_process_name(name: &str) {
    use libc::{prctl, PR_SET_NAME};
    use std::ffi::CString;
    use std::os::raw::c_char;

    let name = CString::new(name).expect("Failed to convert name to CString");
    unsafe {
        let _ = prctl(PR_SET_NAME, name.as_ptr() as *const c_char, 0, 0, 0);
    }
}

pub fn spawn_fake_haproxy() -> (JoinHandle<()>, u16) {
    let binder = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = binder.local_addr().unwrap().port();
    let fake = thread::spawn(move || {
        set_process_name("haproxy");
        for _ in binder.incoming() {}
    });

    (fake, port)
}

pub fn setup_tracing() {
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;
    use tracing_error::ErrorLayer;

    let filter = filter::EnvFilter::builder()
        .parse("renew_certs=debug,info")
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
