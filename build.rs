#[cfg(target_arch="aarch64")]
fn setup_aarch_crosscomp() {
    use std::path::Path;
    use flate2::bufread::GzDecoder;
    use std::io::BufReader;
    use tar::Archive;

    let aarch_musl_cross = Path::new("aarch64-linux-musl-cross");
    if !aarch_musl_cross.is_dir() {
        let bytes = reqwest::blocking::get("https://www.rust-lang.org").unwrap(); //.bytes().unwrap();
        let buf = BufReader::new(bytes);
        let tarfile = GzDecoder::new(buf);
        let mut archive = Archive::new(tarfile);
        archive.unpack(".").unwrap();
    }

    println!(r"cargo:rustc-link-search=aarch64-linux-musl-cross");
    println!(r"cargo:rustc-env=CC=aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc");
    println!(r"cargo:rustc-env=TARGET_CC=aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc");
}

fn main() {
    #[cfg(target_arch="aarch64")]
    setup_aarch_crosscomp();
}
// aarch64-linux-musl-gcc
