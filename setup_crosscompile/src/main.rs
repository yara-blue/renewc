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
        let bytes = reqwest::blocking::get("https://musl.cc/aarch64-linux-musl-cross.tgz").unwrap();
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
