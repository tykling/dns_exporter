Examples
========
This page is a collection of configuration examples for various ``dns_exporter`` usecases.

Configuring ``dns_exporter`` is done with a config file containing modules and referencing those modules in the ``params`` section of the scrape config in ``prometheus.yml``.

This means that the examples on this page are made up of two parts, the first part being the ``dns_exporter.yml`` configuration for the èxporter itself, and the other part being what goes into the ``scrape_jobs`` section of ``prometheus.yml``.

The configuration snippets on this page are all ready to adapt and use.


Monitoring a list of names
--------------------------
Usecase
~~~~~~~
Monitor the MX record for a list of domains.

* All settings defined in the module
* Target used as ``query_name``

``dns_exporter.yml``
~~~~~~~~~~~~~~~~~~~~
The module needs to define the ``query_type`` and the ``server`` to use::

   ---
   modules:
     quad9_mx:
       query_type: "MX"
       server: "dns.quad9.net"
   ...

``prometheus.yml``
~~~~~~~~~~~~~~~~~~
The scrape job needs to:

* Get the list of targets from SD, in this case a list of domains.
* In ``params`` set ``module`` to the value ``quad9_mx``
* In ``relabel_configs`` set the ``query_name`` scrape param to the target
* In ``relabel_configs`` set the standard ``__address__`` and ``instance`` labels

With the ``dns_exporter`` running at ``dnsexp.example.com:15353``::

   scrape_configs:
     - name: "dnsexp_quad9_mx"
       scheme: "https"
       scrape_interval: "10s"
       metrics_path: "/query"
       params:
         module:
           - "quad9_mx"
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

.. Note:: Targets can be from any SD, this example uses ``static_configs``.



Monitoring a list of servers
----------------------------
Usecase
~~~~~~~
Monitor a list of DNS servers. The Prometheus targets are the DNS servers and ``query_name`` and ``query_type`` are defined in the module.

``dns_exporter.yml``
~~~~~~~~~~~~~~~~~~~~
The module needs to define the ``query_name`` to use::

   ---
   modules:
     gmail_mx:
       query_type: "MX"
       query_name: "gmail.com"
   ...

``prometheus.yml``
~~~~~~~~~~~~~~~~~~
The scrape job needs to:

* Get the list of targets from SD, in this case a list of DNS servers.
* In ``params`` set ``module`` to the value ``gmail_mx``
* In ``relabel_configs`` set the ``server`` scrape param to the target
* In ``relabel_configs`` set the standard ``__address__`` and ``instance`` labels

With the ``dns_exporter`` running at ``dnsexp.example.com:15353``::

   scrape_configs:
     - name: "dnsexp_doh_gmail_mx"
       scheme: "https"
       scrape_interval: "10s"
       metrics_path: "/query"
       params:
         module:
           - "doh_gmail_mx"
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

Would make Prometheus scrape the ``MX`` records for ``gmail.com`` every 10 seconds using Googles and Quad9s public DoH servers.
