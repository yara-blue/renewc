use shared_memory::{Shmem, ShmemConf, ShmemError};
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
    fn port(&self) -> u16 {
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

    fn wait_till_done(&self) {
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

        #[allow(clippy::cast_ptr_alignment)] // manually checked
        unsafe {
            port = &mut *raw_ptr.cast::<u16>().cast::<std::sync::atomic::AtomicU16>();
            raw_ptr = raw_ptr.add(16);
            done = &mut *raw_ptr
                .cast::<bool>()
                .cast::<std::sync::atomic::AtomicBool>();
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
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.inner.port()
    }
    #[allow(dead_code)]
    pub fn signal_done(&mut self) {
        self.inner.done();
    }
}

#[allow(clippy::panic)]
#[allow(dead_code)]
#[must_use]
pub fn spawn(name: &str) -> PortUser {
    use fork::{fork, Fork};
    let mut ipc = Ipc::new();
    match fork().unwrap() {
        Fork::Parent(child) => {
            println!("Continuing in parent, child pid: {child}");
            PortUser::from(ipc)
        }
        Fork::Child => {
            proctitle::set_title(name);
            let binder = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = binder.local_addr().unwrap().port();
            ipc.set_port(port);
            ipc.wait_till_done();
            std::process::exit(0)
        }
    }
}
