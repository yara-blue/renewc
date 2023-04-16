// #[cfg(target_arch = "aarch64")]
fn setup_aarch_crosscomp() {
    use flate2::bufread::GzDecoder;
    use std::io::BufReader;
    use std::path::Path;
    use tar::Archive;

    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    compile_error!("only setup to download crosscomp running on x86_64 linux");

    let aarch_musl_cross = Path::new("aarch64-linux-musl-cross");
    if !aarch_musl_cross.is_dir() {
        println!("downloading musl crosscompiler");

        let mut sources = ["https://musl.cc/aarch64-linux-musl-cross.tgz", "https://github.com/tsl0922/musl-toolchains/releases/download/2021-11-23/aarch64-linux-musl-cross.tgz"].into_iter();
        let bytes = loop {
            let source = sources.next().expect("No more mirrors to try");
            match reqwest::blocking::get(source) {
                Ok(bytes) => break bytes,
                Err(_) => {
                    println!("Error trying to download from {source:?}, trying another mirror");
                }
            }
        };

        let buf = BufReader::new(bytes);
        let tarfile = GzDecoder::new(buf);
        let mut archive = Archive::new(tarfile);
        archive.unpack(".").unwrap();
    }
}

fn main() {
    // #[cfg(target_arch = "aarch64")]
    setup_aarch_crosscomp();
}
