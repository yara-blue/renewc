# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] - 2023-05-05

### Fixes
 - orders no longer get stuck at status pending
 - when challenge server is not reachable the error message no longer mentions "a different server malfunctioning"

## [0.2.3] - 2023-05-05

### Added
 - add support for Linux targets with arm or armv7 architecture and hardware floating point unit

## [0.2.2] - 2023-05-05

### Added
 - new install option `download.sh` which picks the right architecture automatically

## [0.2.1] - 2023-05-05

### Fixes
 - Email is now actually added to acme account info

## [0.2.0] - 2023-05-04

### Added
 - Choose between DER and PEM encoding
 - Choose between PEM single file, separate chain, separate private key or all seperate

### Fixes
 - Failed pre-check (existing certificate corrupt) no longer aborts renewal.

## [0.1.1] - 2023-04-20

### Fixed
 - Resolved soundness issue by replacing dependency `atty` with `is-terminal`
