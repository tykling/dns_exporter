Quick Start
===========
To get ``dns_exporter`` up and running quickly you can install and run it without a config file.

.. Tip:: Running without a config file is recommended only for basic usage. Creating a config file with one or more modules is recommended to keep the Prometheus configuration short and readable.

.. Note:: The ``validate_*`` options can *only* be used by setting them in a module. They are not available when running without a config file.

Installation
------------
Installing ``dns_exporter`` can be done from pypi. This is the recommended way to install::

   pip install dns_exporter

You can also checkout the sources from Github and install without pypi::

   git clone https://github.com/tykling/dns_exporter.git
   pip install ./dns_exporter/

.. Warning:: Installing directly from Github with the above command will install the latest unreleased code from the ``develop`` branch. This may not be what you want.


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
To monitor a *list of DNS names* using a *specific DNS server* add a scrape job like this::

   scrape_configs:
     - name: "dnsexp_mx_check"
       scheme: "http"
       scrape_interval: "10s"
       metrics_path: "/query"
       params:
         query_type:
           - "MX"
         server:
           - "dns.google"
       relabel_configs:
         - source_labels: ["__address__"]
           target_label: "__param_query_name"
         - source_labels: ["__address__"]
           target_label: "instance"
         - target_label: "__address__"
           replacement: "dnsexp.example.com:15353"
       static_configs:
         - targets:
           - "gmail.com"
           - "outlook.com"
           - "protonmail.com"

This configuration will scrape the ``dns_exporter`` instance running at ``dnsexp.example.com:15353`` three times, each resulting in a DNS lookup. The DNS lookups will be done over ``UDP`` (the default ``protocol`` setting) using the server ``dns.google``. The DNS lookups will be for the type ``MX`` and for the ``gmail.com``, ``outlook.com``, and ``protonmail.com`` names.

If instead you want to monitor *a specific DNS name* on a *list of DNS servers* use a config like this::

   scrape_configs:
     - name: "dnsexp_soa_check"
       scheme: "http"
       scrape_interval: "10s"
       metrics_path: "/query"
       params:
         query_type:
           - "SOA"
         query_name:
           - "example.com"
       relabel_configs:
         - source_labels: ["__address__"]
           target_label: "__param_server"
         - source_labels: ["__address__"]
           target_label: "instance"
         - target_label: "__address__"
           replacement: "dnsexp.example.com:15353"
       static_configs:
         - targets:
           - "dns.google"
           - "dns.quad9.net"

This configuration will scrape the ``dns_exporter`` instance running at ``dnsexp.example.com:15353`` twice. The DNS lookups will be for the type ``MX`` and for the name ``example.com`` using the servers ``dns.google`` and ``dns.quad9.net``.

.. tip::
   Targets can be anything! The list of targets doesn't have to contain DNS names or DNS servers. It can be anything you want to iterate over in that scrape job - ``query_type``, ``protocol``, or ``family`` for example. Use ``relabel_configs`` to make sure the scrape job labels are correct.


Further Reading
---------------
``dns_exporter`` combined with ``relabel_configs`` is flexible. Read more about the available settings in :doc:`configuration` or go to the :doc:`examples` to learn more.
