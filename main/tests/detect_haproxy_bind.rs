use std::net::TcpListener;
use std::thread::{self, JoinHandle};

use renew_certs::{diagnostics, run, Config};

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

#[cfg(not(target_os = "linux"))]
fn set_process_name(_name: &str) {
    // Do nothing on non-Linux platforms
}

fn spawn_fake_haproxy() -> (JoinHandle<()>, u16) {
    let binder = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = binder.local_addr().unwrap().port();
    let fake = thread::spawn(move || {
        set_process_name("haproxy");
        for _ in binder.incoming() {}
    });

    (fake, port)
}

#[tokio::test]
async fn main() {
    color_eyre::install().unwrap();
    let (_handle, bound_port) = spawn_fake_haproxy();

    let config = Config::test(bound_port);
    run(config, true).await.unwrap();
}
