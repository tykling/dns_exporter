Examples
========
This page is a collection of configuration examples for various ``dns_exporter`` usecases.

Configuring ``dns_exporter`` is done with a config file containing modules and referencing those modules in the ``params`` section of the scrape config in ``prometheus.yml``.

This means that the examples on this page are made up of two parts, the first part being the ``dns_exporter.yml`` configuration for the exporter itself, and the other part being what goes into the ``scrape_jobs`` section of ``prometheus.yml``.

The configuration snippets on this page are all actively `tested in CI <https://github.com/tykling/dns_exporter/blob/main/src/tests/test_examples.py>`_ so they should be ready to adapt and use.


Monitoring a list of names
--------------------------
Usecase
~~~~~~~
Monitor the MX record for a list of domains.

* All settings defined in the module
* Target used as ``query_name``

``dns_exporter.yml``
~~~~~~~~~~~~~~~~~~~~
The module defines the ``query_type``, ``family`` and the ``server`` to use:

.. literalinclude:: ../../tests/prometheus/list_of_names/dns_exporter.yml

``prometheus.yml``
~~~~~~~~~~~~~~~~~~
The scrape job needs to:

* Get the list of targets from SD, in this case a list of names/domains.
* In ``params`` set ``module`` to the value ``quad9_mx``
* In ``relabel_configs`` set the ``query_name`` scrape param to the target
* In ``relabel_configs`` set the standard ``__address__`` and ``instance`` labels.
* In ``relabel_configs`` set the ``monitor`` label to the exporter address.
* Remember to also scrape the internal metrics under ``/metrics``

.. literalinclude:: ../../tests/prometheus/list_of_names/prometheus.yml

.. Note:: Targets can be from any SD, this example uses ``static_configs``.

This would make Prometheus scrape the ``MX`` records for ``gmail.com`` and ``outlook.com`` every 10 seconds using ``dns.quad9.net``.

``Example Metrics``
~~~~~~~~~~~~~~~~~~~
.. Note::  These metrics are taken directly from the exporter, so they don't have the Prometheus added ``instance`` and ``job`` labels yet

Metrics returned for target ``gmail.com``:

.. literalinclude:: ../../tests/prometheus/list_of_names/gmail.com.txt


Metrics returned for target ``outlook.com``:

.. literalinclude:: ../../tests/prometheus/list_of_names/outlook.com.txt


Monitoring a list of servers
----------------------------
Usecase
~~~~~~~
Monitor a list of DNS servers. The Prometheus targets are the DNS servers and ``query_name`` and ``query_type`` are defined in the module.

``dns_exporter.yml``
~~~~~~~~~~~~~~~~~~~~
The module defines the ``query_type``, ``query_name`` and the ``family`` to use:

.. literalinclude:: ../../tests/prometheus/list_of_servers/dns_exporter.yml

``prometheus.yml``
~~~~~~~~~~~~~~~~~~
The scrape job needs to:

* Get the list of targets from SD, in this case a list of DNS servers.
* In ``params`` set ``module`` to the value ``gmail_mx_v4``
* In ``relabel_configs`` set the ``server`` scrape param to the target
* In ``relabel_configs`` set the standard ``__address__`` and ``instance`` labels
* In ``relabel_configs`` set the ``monitor`` label to the exporter address.
* Remember to also scrape the internal metrics under ``/metrics``

With the ``dns_exporter`` running at ``dnsexp.example.com:15353``:

.. literalinclude:: ../../tests/prometheus/list_of_servers/prometheus.yml

Would make Prometheus scrape the ``MX`` records for ``gmail.com`` every 10 seconds using Googles and Quad9s public DoH servers.

``Example Metrics``
~~~~~~~~~~~~~~~~~~~
.. Note::  These metrics are taken directly from the exporter, so they don't have the Prometheus added ``instance`` and ``job`` labels yet

Metrics returned for target ``dns.google``:

.. literalinclude:: ../../tests/prometheus/list_of_servers/dns.google.txt


Metrics returned for target ``dns.quad9.net``:

.. literalinclude:: ../../tests/prometheus/list_of_servers/dns.quad9.net.txt
