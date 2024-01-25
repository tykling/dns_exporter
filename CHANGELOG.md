# Changelog

All notable changes to `dns_exporter` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [v0.3.0] - 2024-01-25

### Changed
- Split code into seperate modules
- Rename `dnsexp_dns_time_seconds` to `dnsexp_dns_query_time_seconds` and change from Histogram to Gauge
- Rename `dnsexp_dns_success` to `dnsexp_dns_query_success`
- Rename `dnsexp_dns_failure_reason` to `dnsexp_dns_query_failure_reason`
- Rename `dnsexp_dns_record_ttl_seconds` to `dnsexp_dns_response_rr_ttl_seconds` and change from Histogram to Gauge

## Added
- Command-line option to set listen IP, use `-L` or `--listen-ip`. Default is `127.0.0.1`.
- Unit tests


## [v0.2.0] - 2023-04-12

### Changed
- Split code into multiple modules

### Added
- Write unit tests
- Write documentation

### Fixed
- Many, many bugs while writing unit tests


## [v0.2.0-beta3] - 2023-01-09

### Changed
- Removed the config file requirement
- Removed the requirement to supply a module in every scrape request
- Updated README.md with more information


## [v0.2.0-beta2] - 2023-01-08

This was the first public pre-release.

### Added

- CHANGELOG.md
- release.sh
