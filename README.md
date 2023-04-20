> **Certificate renewal, with advanced diagnostics without installing anything**

[![Security audit](https://github.com/dvdsk/renewc/actions/workflows/schedualed-audit.yml/badge.svg)](https://github.com/dvdsk/renewc/actions/workflows/schedualed-audit.yml)
[![Tests](https://github.com/dvdsk/renewc/actions/workflows/testing.yml/badge.svg)](https://github.com/dvdsk/renewc/actions/workflows/testing.yml)
[![License](https://img.shields.io/badge/license-GPL3-blue?style=round-square)](LICENSE)

See also:
 - [Install](#Install)
 - [Example](#Example)
 - [Changelog](CHANGELOG.md)

Certificate renewal can be quite fragile. This as a renewal tool that runs without install and does not need anything installed. If anything goes south during renewal it does not just report an error. It will try and find out what is wrong and give you a detailed report. For certificate renewal we use [instant-acme](https://crates.io/crates/instant-acme). 

## Features 
 - Request or renews a *Let's Encrypt* certificate
 - Runs on any Linux system without setup thanks to [musl](https://musl.libc.org/about.html)
 - Asks before dangerous actions 
    - replacing production with staging
    - not due for renewal
 - Helps out when things go wrong, see [diagnostics](#diagnostics) 
 - Set up a *systemd* service for auto-renewal
 - Reload a *systemd* service once the certificate has been renewed

## Diagnostics
Currently *renewc* can investigate and advise these situations:

 - HTTP traffic for the domain not routing to *renewc*  
*advices to check if ports are forwarded correctly*
 - A program binding to the port:  
*reports the name and the path to that program, so you can shut it down*
 - HAProxy forwarding traffic from the port:  
*looks at HAProxy's configs and tells you what port to use instead*
 - Using a port below 1025 without sudo:  
*advices to call *renewc* using sudo*

We hope to expand this list in the near future, PRs are welcome.

### Example
Requesting a certificate on port 80 while running traffic on port 80 through a HAProxy. The renewal fails, however renewc investigated and found out HAProxy is forwarding traffic to a local port.

```
Error:
   0: Challenge server ran into problem
   1: The port is already in use
   2: error creating server listener: Address in use (os error 98)
   3: Address in use (os error 98)

Note: The port is being used by:
	- `haproxy`
		path: /usr/sbin/haproxy
Note: haproxy is forwarding port 80 to: 34320
Suggestion: try calling renewc with: `--port 34320`
```

## Install
Download the binary for your platform:
- x86/x64 (normal pc's): [x64](https://github.com/dvdsk/renewc/releases/latest/download/renewc_x64)  
```bash
curl -L https://github.com/dvdsk/renewc/releases/latest/download/renewc_x64 -o renewc
``` 
- arm based systems (raspberry pi): [aarch64](https://github.com/dvdsk/renewc/releases/latest/download/renewc_aarch64)
```bash
curl -L https://github.com/dvdsk/renewc/releases/latest/download/renewc_aarch64 -o renewc
``` 

Currently, we only target Linux PR's targeting other systems are welcome.

## Basic usage
To request or renew a certificate for `example.org` and store it at `/where/to/store/cert` run: 
```
renewc run --domains example.org --path /where/to/store/cert
``` 
See `renewc help` for other options such as `install`. Call `renewc <option> --help` to see details.

## Compiling from source
Set up the cross-compiler by running `cargo r` inside `setup_crosscompile`. This takes care of downloading a statically linked musl based GCC cross-compiler. Using it static binaries for the C dependencies are created that are used while linking the Rust code. 

The resulting binary will run on **any aarch64-linux target** that is not running an ancient kernel.

## Contributions
Did you run into a problem with your system/setup while renewing certificates? Did it take you a second to figure it out? Please make an issue, so we can see if it can be added to the diagnostics. 

I welcome PRs.

