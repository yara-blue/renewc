Zero runtime dependencies crosscompiled (for aarch64) Http01 CertBot alternative 

With Certbot being quite fragile and not always available I build this as an alternative. The certificate renewal is done through [instant-acme](https://crates.io/crates/instant-acme). The build script (`build.rs`) takes care of downloading a statically linked musl based gcc crosscompiler. Using it static binaries for the C dependencies are created that are used while linking the Rust code. 

The resulting binary will run on any aarch64-linux target that is not running an ancient kernel.
