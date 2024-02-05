# Changelog

All notable changes to `dns_exporter` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## unreleased

## Added
- RELEASE.md file describing how to do a release
- `build` module to the `dev` extras in `pyproject.toml`
- Add a new `dnsexp_failure_reason` Counter metric with a `reason` label. This is now the place to track failures.
- Python 3.12 support

## Changed
- Delete the `develop` branch, `main` is the new default branch. Update `RELEASE.md` to reflect the change.
- Update some development dependencies
- Major refactor: move DNS lookup to a custom `prometheus_client.registry.Collector` class in `collector.py`

## Removed
- Removed the `dnsexp_dns_query_failure_reason` Enum from /query output.
- Removed the `dnsexp_dns_failures_total` Counter metric from /metrics output.

## Fixed
- DNS over QUIC support now works. Default port is 853 as per https://www.rfc-editor.org/rfc/rfc9250.html#name-port-selection


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
- Github action to build a new dockerhub image when a new tag is pushed
- Python3.12 is now tested in CI
- Add a Dockerfile (thanks @dallemon)


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
