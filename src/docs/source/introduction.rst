Introduction
============

What
----
``dns_exporter`` is a `multi-target <https://prometheus.io/docs/guides/multi-target-exporter/>`_ `Prometheus <https://prometheus.io/>`_ exporter with an exclusive focus on DNS monitoring. It is built on the excellent libraries `dnspython <https://github.com/rthalley/dnspython>`_ and the Prometheus `Python client library <https://github.com/prometheus/client_python>`_.

``dns_exporter`` can be used to monitor availability and performance of DNS servers, and to validate the responses they return. It can monitor recursive and authoritative servers regardless of the software they run. You can use it to make sure your (or your providers) DNS servers are sending the replies you expect and configure `Prometheus <https://prometheus.io/>`_ and `Alertmanager <https://prometheus.io/docs/alerting/latest/alertmanager/>`_ to notify you if something stops working.

How
---
``dns_exporter`` works similar to the `Blackbox exporter <https://github.com/prometheus/blackbox_exporter>`_ where Prometheus asks the exporter to scrape the target, rather than the exporter itself being the target. This is called the `Multi Target Exporter Pattern <https://prometheus.io/docs/guides/multi-target-exporter/>`_. It is typically used in black-box style exporters where 1) the thing you are monitoring is not under your control, or 2) you want to measure the path as well. Often when monitoring DNS both 1) and 2) are relevant.

This means that for each scrape Prometheus speaks HTTP to the ``dns_exporter`` which then speaks DNS with the target DNS server and returns the resulting metrics over HTTP to Prometheus. ``dns_exporter`` supports doing DNS queries over plain port 53 ``UDP`` and ``TCP``, as well as ``DoT``, ``DoH`` and ``DoQ``.

Why
---
``dns_exporter`` is inspired by the DNS features of the `Blackbox exporter <https://github.com/prometheus/blackbox_exporter>`_ - in fact some of the validation settings are named after the corresponding Blackbox Exporter settings to make migration easier. ``dns_exporter`` can do the same DNS monitoring as Blackbox Exporter, but it exports more metrics, supports more protocols and more validation types.
