Changelog
=========

All notable changes to ``dns_exporter`` will be documented in this file.

The format is based on `Keep a
Changelog <https://keepachangelog.com/en/1.0.0/>`__, and this project
adheres to `Semantic
Versioning <https://semver.org/spec/v2.0.0.html>`__.

v1.1.0-beta4 - 2025-02-22
-------------------------

Changed
~~~~~~~

-  Better metadata for Docker image builds


v1.1.0-beta3 - 2025-02-18
-------------------------

Fixed
~~~~~

-  Docker image workflow was broken for some platforms


v1.1.0-beta2 - 2025-02-18
-------------------------

Changed
~~~~~~~

-  Update linters in ``.pre-commit-config.yaml`` and fix new linting issues
-  Convert CHANGELOG.md to CHANGELOG.rst and include in sphinx build/RTD
-  Rework Dockerfile, push images to both Dockerhub and Github


[v1.1.0-beta1] - 2025-01-26
---------------------------

Added
~~~~~

-  DNS-over-HTTP3 support: New protocol ``doh3`` was added for doing
   DNS-over-QUIC wrapped in HTTP3, aka DNS-over-HTTP3.
-  Digestabot introduced to keep docker image digests up-to-date.
-  Proxy support for DoQ and DoH3. Issue #96.

Changed
~~~~~~~

-  Bump dnspython dependency minimum version to 2.7.0
-  Pass custom CA path as ssl.SSLContext for DoH2 requests to silence
   httpx DeprecationWarning
-  Refactor verify logic into new seperate methods ``get_tls_context()``
   and ``get_tls_verify()``
-  Verify that the configured ``verify_certificate_path`` exists in the
   filesystem, raise ConfigError if not.
-  Improve certificate related unit tests (parametrize and add more
   tests)
-  Move ``test_internal_metrics()`` test to seperate file, write metrics
   to temp file to ease debugging when the test breaks (which happens
   often).
-  Update and simplify Dockerfile
-  Move coverage.py, pytest and tox config to ``pyproject.toml``.

Fixed
~~~~~

-  Docs url in package metadata (used for example in PyPi sidebar).
   Issue #11.
-  Make unit tests, mypy and linters happy after DoH3 addition.
-  Re-enable custom CA path support for DoQ. Only works with a CA file,
   not with a CA dir, for now (#132).
-  Socket reuse bug introduced with proxy support for QUIC based
   protocols.


[v1.0.0] - 2024-03-07
---------------------

1.0.0 represents the first stable release of ``dns_exporter``. Future
changes (especially concerning metrics naming and labels) will follow
semver rules regarding versioning. The goal is to never introduce
dashboard breaking changes to metrics without bumping the major version.

The details about all the changes through the pre-releases are included
below, but are probably only interesting if you have been using a
pre-1.0 version. If you have existing dashboards with pre-1.0 data you
will need to create new, seperate dashboards for 1.0 because the metrics
have changed so much. You can use
https://grafana.com/grafana/dashboards/20617-dns-exporter/ as a starting
point for your own dashboards.


[v1.0.0-rc4] - 2024-03-06
-------------------------

Changed
~~~~~~~

-  Remove wrong buckets on response time Histogram, replace with default
   buckets


[v1.0.0-rc3] - 2024-03-06
-------------------------

Fixed
~~~~~

-  Catch ``httpx.ConnectTimeout`` from protocol ``doh`` as failure
   reason ``timeout``

Changed
~~~~~~~

-  Add more labels to the ``dnsexp_scrape_failures_total`` metric so it
   has all the same labels as ``dnsexp_dns_query_time_seconds`` in
   addition to the ``reason`` label.


[v1.0.0-rc2] - 2024-03-06
-------------------------

Fixed
~~~~~

-  Always send Content-Length header for metrics responses
-  Do not overwrite ``no_nsid`` placeholder if a blank NSID is received
   from server (to avoid blank labels)

Changed
~~~~~~~

-  Add the ``monitor`` label in all examples, also the ones scraping
   internal metrics


[v1.0.0-rc1] - 2024-03-06
-------------------------

Changed
~~~~~~~

-  Minimum supported DNSPython version is now 2.5.0
-  Log at level warning when encountering an unknown failure
-  Remove failure reason ``connection_refused`` and report it as
   ``connection_error`` along with the rest of socket related errors.
-  Remove ``dnsexp_failures_total`` from per-scrape metrics. Failure
   reasons are now tracked only under ``/metrics``.
-  Switch from ``http.server.HTTPServer`` to
   ``http.server.ThreadingHTTPServer``
-  Add new failure reason ``invalid_response_statuscode`` for DoH
   failures.
-  The default for the ``collect_ttl_rr_value_length`` has been changed
   from ``255`` to ``50`` to reduce label cardinality.
-  Docs: Mention the importance of scraping internal metrics under
   ``/metrics``
-  Docs: Mention adding a ``monitor`` label to identify the exporter in
   use, for setups where multiple instances of ``dns_exporter`` is
   running.
-  Update unit tests for all of the above


Fixed
~~~~~

-  Always send content-length header for static responses (#100, thanks
   @jcodybaker!)


[v1.0.0-beta6] - 2024-03-01
---------------------------

Added
~~~~~

-  Unit tests for proxy code
-  Unit tests for new code introduced to make ruff happy
-  New ``collect_ttl`` setting to control collection of per-RR TTL
   metrics. Default is true.
-  New ``verify_certificate`` bool setting to control validation of
   certificates on encrypted protocols. Default is true.
-  New ``verify_certificate_path`` str setting to override the system CA
   when validating certificates on encrypted protocols. Leave empty to
   use the default system CA. Default is an empty string.

Changed
~~~~~~~

-  Replace black, flake8, isort, pydocstyle with ruff
-  Some refactoring to reduce complexity and ease testing
-  Much linting
-  Move coverage.py config to .coveragerc to make showing measurement
   contexts in coverage html work
-  Proxy support for DoQ disabled, pending next dnspython release with
   https://github.com/rthalley/dnspython/pull/1060
-  Improve unit tests
-  Polish dockerhub action a bit (thanks @dallemon!)
-  Re-add custom histogram buckets for metric
   ``dnsexp_dns_responsetime_sedonds`` from 1 second doubling until
   4194304 seconds (48 days).
-  Build docs in ``pre-commit`` to avoid breaking them
-  Include ``protocol``, ``server``, and ``proxy`` labels in the
   ``dnsexp_scrape_failures_total`` Counter metric.

Fixed
~~~~~

-  Fixed a bug which made ``fail_if_all_match_regexp`` validation
   succeed on the first matching RR (not considering further RRs).


[v1.0.0-beta5] - 2024-02-20
---------------------------

Changed
~~~~~~~

-  Updated some dev and test dependencies
-  Improve debug logging
-  Enable proxy support for all protocols except DoT


[v1.0.0-beta4] - 2024-02-19
---------------------------

Fixed
~~~~~

-  Update codecov GH action to silence warning in CI
-  Handle errors in unit test setup better
-  Wrote a real describe() method in the collector
-  Support dnspython 2.6.0 as well as earlier versions
-  Add ttl metrics for all rrs.
-  Improve logformat used during unit tests

Added
~~~~~

-  Basic proxy support for plain TCP DNS lookups, supported proxy types
   are SOCKS4, SOCKS5 and HTTP.
-  Introduced pytest-mock test dependency to help with testing proxy
   code
-  Three new failure modes: ``invalid_request_proxy``,
   ``connection_error``, ``connection_refused``

Changed
~~~~~~~

-  Suppress warnings at runtime (to silence dependencies)
-  Fail with a nice message if the port is in use when starting the
   exporter

[v1.0.0-beta3] - 2024-02-15
---------------------------

Fixed
~~~~~

-  DockerHub workflow unbroken, take 2


[v1.0.0-beta2] - 2024-02-10
---------------------------

Fixed
~~~~~

-  DockerHub workflow unbroken


[v1.0.0-beta1] - 2024-02-09
---------------------------

Changed
~~~~~~~

-  Update CHANGELOG
-  Add more badges to README.md


[v1.0.0-alpha1] - 2024-02-08
----------------------------

Version 1.0.0 is a major refactor. It changes some metric names and has
many internal changes. It also enables DoQ support. Most stuff should
work as it did before 1.0.0 though.

The metrics exposed under /query (per-scrape metrics) are now:

-  dnsexp_dns_query_time_seconds (Gauge, unchanged)
-  dnsexp_dns_query_success (Gauge, unchanged)
-  dnsexp_dns_response_rr_ttl_seconds (Gauge, unchanged)
-  dnsexp_failures_total (Counter, renamed and changed from Enum)

The metrics exposed under /metrics (persistent exporter-internal
metrics) are now:

-  dnsexp_build_version (Info, unchanged)
-  dnsexp_http_requests_total (Counter, unchanged)
-  dnsexp_http_responses_total (Counter, unchanged)
-  dnsexp_dns_queries_total (Counter, unchanged)
-  dnsexp_dns_responsetime_seconds (Histogram, renamed and changed from
   Counter)
-  dnsexp_scrape_failures_total (Counter, renamed and got a reason
   label)

Further changes are mostly technical details.

Added
~~~~~

-  RELEASE.md file describing how to do a release
-  ``build`` module to the ``dev`` extras in ``pyproject.toml``
-  Python 3.12 support
-  Automatic DockerHub upload of containers when new releases are tagged
-  Automatic PyPi upload of packages when new releases are tagged

Changed
~~~~~~~

-  Delete the ``develop`` branch, ``main`` is the new default branch.
   Update ``RELEASE.md`` to reflect the change.
-  Update some development dependencies
-  Major refactor: move DNS lookup to a custom
   ``prometheus_client.registry.Collector`` class in ``collector.py``

Fixed
~~~~~

-  DNS over QUIC support now works. Default port is 853 as per
   https://www.rfc-editor.org/rfc/rfc9250.html#name-port-selection


[v0.3.0] - 2024-01-25
---------------------


Changed
~~~~~~~

-  Split code into seperate modules
-  Rename ``dnsexp_dns_time_seconds`` to
   ``dnsexp_dns_query_time_seconds`` and change from Histogram to Gauge
-  Rename ``dnsexp_dns_success`` to ``dnsexp_dns_query_success``
-  Rename ``dnsexp_dns_failure_reason`` to
   ``dnsexp_dns_query_failure_reason``
-  Rename ``dnsexp_dns_record_ttl_seconds`` to
   ``dnsexp_dns_response_rr_ttl_seconds`` and change from Histogram to
   Gauge


Added
~~~~~

-  Command-line option to set listen IP, use ``-L`` or ``--listen-ip``.
   Default is ``127.0.0.1``.
-  Unit tests
-  Github action to build a new dockerhub image when a new tag is pushed
-  Python3.12 is now tested in CI
-  Add a Dockerfile (thanks @dallemon)


[v0.2.0] - 2023-04-12
---------------------

Changed
~~~~~~~

-  Split code into multiple modules

Added
~~~~~

-  Write unit tests
-  Write documentation

Fixed
~~~~~

-  Many, many bugs while writing unit tests


[v0.2.0-beta3] - 2023-01-09
---------------------------

Changed
~~~~~~~

-  Removed the config file requirement
-  Removed the requirement to supply a module in every scrape request
-  Updated README.md with more information


[v0.2.0-beta2] - 2023-01-08
---------------------------

This was the first public pre-release.

Added
~~~~~

-  CHANGELOG.md
-  release.sh
