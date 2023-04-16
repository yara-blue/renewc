> **Zero runtime dependencies Http01 CertBot alternative**

Certbot can be quite fragile and not always available. This as an alternative, with extensive diagnostics for when things do go wrong. The certificate renewal itself is done through [instant-acme](https://crates.io/crates/instant-acme). 

## Features 
 - Request or renews a *Let's Encrypt* certificate
 - Asks before dangerous actions 
    - replacing production with staging
    - not due for renewal
 - Helps out when things go wrong, see the example below
 - Install a *systemd* service for auto-renewal
 - Reload a *systemd* service once the certificate has been renewed

## Example
Requesting a certificate on port 80 while running traffic on port 80 through a HAProxy. The renewal fails, however renewc investigated and found out HAProxy is forwarding traffic to a local port.

```
```
Though impressive only HAProxy configs are currently analyzed in this way. I welcome PR's extending the diagnostics.

## Usage
Run `renewc run --domains example.org --path /where/to/store/cert` to request or renew a certificate for `example.org` and store it at `/where/to/store/cert`.

## Compiling from source
Setup the cross compiler by running `cargo r` inside `setup_crosscompile`. This takes care of downloading a statically linked musl based gcc crosscompiler. Using it static binaries for the C dependencies are created that are used while linking the Rust code. 

The resulting binary will run on **any aarch64-linux target** that is not running an ancient kernel.
