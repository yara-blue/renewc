# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2023-11-25

### Changed
 - Asks the use to confirm the request if the new certificate would miss domains that are valid with the current certificate. Rejects renewal if not running interactively (such as from a shell command).

## [0.3.2] - 2023-11-07

### Fixes
 - Number of hours in diagnostic message no longer add the number of days*24 that was just printed before them

## [0.3.1] - 2023-06-11

### Added
 - Note the current machines local IP when the challenge server is not reachable

## [0.3.0] - 2023-06-11

### Added
 - Print a short summary including paths after writing files to disk

### Changes
 - PEM output option now follows [rfc4346](https://www.rfc-editor.org/rfc/rfc4346#section-7.4.2) certificate lists order
 - Challenge verification may take longer now, user is informed in if it takes long.

### Fixes
 - Full paths to output files are no longer miss their parent directory if it contained a dot

## [0.2.6] - 2023-06-03

### Added
 - Allow path arguments with or without the correct extension
 - Warn user before renewal if path has (wrong) extension

## [0.2.5] - 2023-06-02

### Fixes
 - Continue y/n no longer continues when choosing n

## [0.2.4] - 2023-06-02

### Fixes
 - Argument `reload` and `output` are now optional independent of each other

### Changes
 - Now use `--reload` and `--output` to specify the output format and whether to reload a SystemD service.

## [0.2.3] - 2023-06-02

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
