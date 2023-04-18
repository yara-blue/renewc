use shared_memory::*;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::thread;
use std::time::Duration;

#[allow(dead_code)]
struct Ipc {
    port: &'static mut AtomicU16,
    done: &'static mut AtomicBool,
    mem: Shmem,
}

impl Ipc {
    pub fn port(&self) -> u16 {
        let mut port;
        loop {
            port = self.port.load(Ordering::Relaxed);
            if port != 0 {
                break port;
            }
        }
    }

    fn set_port(&mut self, port: u16) {
        self.port.store(port, Ordering::Relaxed);
    }

    pub fn wait_till_done(&self) {
        while !self.done.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn done(&mut self) {
        self.done.store(true, Ordering::SeqCst);
    }

    fn new() -> Ipc {
        let mem = match ShmemConf::new().size(4096).create() {
            Ok(m) => m,
            Err(ShmemError::LinkExists) => panic!("Link should be created before forking"),
            Err(e) => panic!("Unable to create shmem flink: {e}"),
        };

        let mut raw_ptr = mem.as_ptr();
        let port: &mut AtomicU16;
        let done: &mut AtomicBool;

        unsafe {
            port = &mut *(raw_ptr as *mut u16 as *mut AtomicU16);
            raw_ptr = raw_ptr.add(16);
            done = &mut *(raw_ptr as *mut bool as *mut AtomicBool);
        }

        if mem.is_owner() {
            port.store(0, Ordering::SeqCst);
            done.store(false, Ordering::SeqCst);
        } else {
            thread::sleep(Duration::from_secs(1));
        }
        Self { port, done, mem }
    }
}

pub struct PortUser {
    inner: Ipc,
}

impl PortUser {
    fn from(inner: Ipc) -> Self {
        Self { inner }
    }
    pub fn port(&self) -> u16 {
        self.inner.port()
    }
    pub fn signal_done(&mut self) {
        self.inner.done()
    }
}

#[allow(clippy::panic)]
#[must_use]
pub fn spawn_fake_haproxy() -> PortUser {
    use fork::{fork, Fork};
    let mut ipc = Ipc::new();
    match fork().unwrap() {
        Fork::Parent(child) => {
            println!("Continuing in parent, child pid: {}", child);
            return PortUser::from(ipc);
        }
        Fork::Child => {
            proctitle::set_title("haproxy");
            let binder = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = binder.local_addr().unwrap().port();
            ipc.set_port(port);
            ipc.wait_till_done();
            std::process::exit(0)
        }
    }
}

pub fn setup_tracing() {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::filter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

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
