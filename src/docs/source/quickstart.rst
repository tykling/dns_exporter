Quick Start
===========
To get ``dns_exporter`` up and running quickly you can install and run it without a config file.

.. Tip:: Running without a config file is recommended only for basic usage. Creating a config file with one or more modules is recommended to keep the Prometheus configuration short and readable.

.. Note:: The ``validate_*`` options can *only* be used by setting them in a module. They are not available when running without a config file.

Installation
------------
Installing ``dns_exporter`` can be done from pypi. This is the recommended way to install::

   pip install dns_exporter

There is also a Docker image so you can get your container on::

   docker run -p 15353:15353 tykling/dns_exporter:latest

If you need more logging from the container you can run the exporter in debug mode::

   docker run -p 15353:15353 tykling/dns_exporter:latest -d

You can mount your own config in the container thusly::

   docker run -p 15353:15353 -v ./dns_exporter_example.yml:/home/nonroot/dns_exporter.yml tykling/dns_exporter:latest

You can also checkout the sources from Github and install directly::

   git clone https://github.com/tykling/dns_exporter.git
   pip install ./dns_exporter/

.. Warning:: Installing directly from Github with the above command will install the latest unreleased code from the ``main`` branch. This may not be what you want.


Running ``dns_exporter``
------------------------
Run the ``dns_exporter`` command to start the exporter and it should be ready to serve requests immediately::

   $ dns_exporter
   2023-04-10 11:43:48 +0200 dns_exporter INFO DNSExporter.main():110:  dns_exporter v0.2.0b4.dev19+g8f385af.d20230410 starting up - logging at level INFO

If you need more logging you can use ``-d`` or ``--debug``::

   $ dns_exporter -d
   2023-04-10 11:43:52 +0200 dns_exporter INFO DNSExporter.main():110:  dns_exporter v0.2.0b4.dev19+g8f385af.d20230410 starting up - logging at level DEBUG
   2023-04-10 11:43:52 +0200 dns_exporter DEBUG DNSExporter.main():140:  No -c / --config-file found so a config file will not be used. No modules loaded.
   2023-04-10 11:43:52 +0200 dns_exporter DEBUG DNSExporter.main():154:  Ready to serve requests. Starting listener on 127.0.0.1 port 15353...

If you want to use a config file you can use ``-c`` or ``--config-file``::

   $ dns_exporter -c dns_exporter.yml 
   2023-04-10 11:47:05 +0200 dns_exporter INFO DNSExporter.main():110:  dns_exporter v0.2.0b4.dev19+g8f385af.d20230410 starting up - logging at level INFO
   2023-04-10 11:47:05 +0200 dns_exporter INFO DNSExporter.configure():128:  32 modules loaded OK.


Configuring Prometheus
----------------------
``dns_exporter`` serves internal metrics (including details about failure reasons) under ``/metrics`` while the endpoint for doing DNS lookups is ``/query``. Make sure you always configure Prometheus to scrape the internal metrics (under ``/metrics``) in addition to any DNS scrape jobs you configure.

These examples use ``static_configs`` but any type of Prometheus Service Discovery can be used.

To monitor a *list of DNS names* using a *specific DNS server* add a scrape job like this:

.. literalinclude:: ../../tests/prometheus/list_of_names/prometheus.yml

This configuration will scrape the ``dns_exporter`` instance running at ``dnsexp.example.com:15353`` two times, resulting in two DNS lookups. The DNS lookups will be done over ``UDP`` (the default ``protocol`` setting) using the server ``dns.google``. The DNS lookups will be for the type ``MX`` and for the ``gmail.com`` and ``outlook.com`` names.

If instead you want to monitor *a specific DNS name* on a *list of DNS servers* use a config like this:

.. literalinclude:: ../../tests/prometheus/list_of_servers/prometheus.yml

This configuration will scrape the ``dns_exporter`` instance running at ``dnsexp.example.com:15353`` twice. The DNS lookups will be for the type ``MX`` and for the name ``example.com`` using the servers ``dns.google`` and ``dns.quad9.net``.

.. tip::
   The list of targets in the Prometheus scrape job can be anything! The list doesn't have to contain DNS names or DNS servers. It can be anything you want to iterate over in that scrape job - ``query_type``, ``protocol``, or ``family`` for example. Use ``relabel_configs`` to make sure the scrape job labels are correct.

.. Note:: The ``monitor`` label in the Prometheus ``relabel_configs`` is included to be able to tell multiple instances of ``dns_exporter`` apart. It is used in the official Grafana dashboards for ``dns_exporter``.


Grafana Dashboard
-----------------
There is a `Grafana dashboard <https://grafana.com/grafana/dashboards/20617-dns-exporter/>`_ you can use as a starting point for your own dashboards.

.. Note:: This Grafana dashboard requires use of the ``monitor`` label shown in the Prometheus ``relabel_configs`` examples. If your SD has some other way of discerning multiple exporters you will need to change the dashboard to match your requirements.


Further Reading
---------------
``dns_exporter`` combined with ``relabel_configs`` is flexible. Read more about the available settings in :doc:`configuration` or go to the :doc:`examples` to learn more.
