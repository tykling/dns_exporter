Configuration
=============
Configuring ``dns_exporter`` is a matter of defining defining some configuration modules in ``dns_exporter.yml`` and then using those modules in the Prometheus scrape jobs.

``dns_exporter`` is flexible and supports many usecases. Go directly to the :doc:`examples` section or read on for the details on configuring ``dns_exporter``.


Precedence
----------
Defaults have the lowest precedence, if a module is used it has medium precedence, and the querystring has highest precedence.

For example, the default value for the ``timeout`` configuration key is ``5.0`` (seconds). If a scrape then asks for a module which sets the ``timeout`` to ``3.0``, and the same scrape also sets the querystring parameter ``timeout`` to ``1.0``, then the effective timeout setting for that scrape would be ``1.0``.


Settings
--------
``dns_exporter`` comes with the following settings and defaults. All scrapes are based on these defaults plus whatever is changed in that specific scrape job:

+-----------------------------+-----------------+------------------------------------------------------------+
| Config Key                  | Default         | Notes                                                      |
+=============================+=================+============================================================+
| ``module``                  | ``none``        | A module from the config file.                             |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``edns``                    | ``true``        | Enables EDNS0                                              |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``edns_do``                 | ``false``       | Enables the DO flag                                        |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``edns_nsid``               | ``true``        | Enable EDNS NSID option                                    |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``edns_bufsize``            | ``1232``        | Sets the EDNS0 bufsize                                     |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``edns_pad``                | ``0``           | Set EDNS0 padding size                                     |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``family``                  | ``ipv6``        | Must be set to ``ipv6`` or ``ipv4``                        |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``ip``                      | ``none``        | Override server hostname DNS lookup                        |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``protocol``                | ``udp``         | ``udp``, ``tcp``, ``udptcp``, ``dot``, ``doh``, or ``doq`` |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``query_class``             | ``IN``          | ``IN`` and ``CHAOS`` are supported.                        |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``query_name``              | ``none``        | The name to use in the DNS query                           |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``query_type``              | ``A``           | ``A``, ``AAAA``, ``MX``, ``TXT`` etc. or use ``TYPEnn``    |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``recursion_desired``       | ``true``        | Sets the ``RD`` flag in the query.                         |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``server``                  | ``none``        | The DNS server to use                                      |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``timeout``                 | ``5.0``         | Query timeout in seconds.                                  |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``validate_answer_rrs``     | ``none``        | Can only be defined in modules in ``dns_exporter.yml``     |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``validate_authority_rrs``  | ``none``        | Can only be defined in modules in ``dns_exporter.yml``     |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``validate_additional_rrs`` | ``none``        | Can only be defined in modules in ``dns_exporter.yml``     |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``validate_response_flags`` | ``none``        | Can only be defined in modules in ``dns_exporter.yml``     |
+-----------------------------+-----------------+------------------------------------------------------------+
| ``valid_rcodes``            | ``NOERROR``     | Comma seperated RCODEs to consider valid.                  |
+-----------------------------+-----------------+------------------------------------------------------------+

Each of these configuration keys can be set in modules in ``dns_exporter.yml``. With the exception of the ``validate_*`` settings all of these can also be changed in the ``params`` section of the scrape job, and as target labels in SD.

The following section describes each setting.


``module``
~~~~~~~~~~
Setting ``module`` in the scrape querystring makes ``dns_exporter`` use the named module to change the default settings. Modules are read from the ``dns_exporter.yml`` when the exporter is started.


``edns``
~~~~~~~~
This bool enables ``EDNS0`` in the outgoing DNS query.

The default value is ``True``.


``edns_do``
~~~~~~~~~~~
This bool enables the ``EDNS0`` ``DO`` flag in the outgoing DNS query. This setting has no effect if ``edns`` is ``False``.

The default value is ``False``.


``edns_nsid``
~~~~~~~~~~~~~
This bool enables the ``EDNS0`` ``nsid`` option in the outgoing DNS query. This setting has no effect if ``edns`` is ``False``. If no ``nsid`` is received in the response the ``nsid`` metric label is set to the value ``no_nsid``.

The default value is ``True``.


``edns_bufsize``
~~~~~~~~~~~~~~~~
This int sets the ``EDNS0`` buffer size in the outgoing DNS query. This setting has no effect if ``edns`` is ``False``.

The default value is ``1232``.


``edns_pad``
~~~~~~~~~~~~
This int sets the ``EDNS0`` padding option to the specified number of bytes. This setting has no effect if ``edns`` is ``False``.

The default value is ``0``.


``family``
~~~~~~~~~~
This setting decides the IP family to use, ``ipv4`` or ``ipv6``. This setting affects the DNS lookup made when the ``server`` setting is a hostname which needs to be resolved.

* If ``family`` is ``ipv4`` then the DNS lookup will look for an ``A`` record.
* If ``family`` is ``ipv6`` then the DNS lookup will look for an ``AAAA`` record.

This setting must match the family of the ``ip`` setting. It is considered invalid to set ``family`` to ``ipv4`` and ``ip`` to an IPv6 address, and vice versa.

The default value is ``ipv6``.


``ip``
~~~~~~
This setting sets IP address to use instead of doing a DNS lookup when ``server`` is a hostname. The address family of this setting must match the ``family`` setting.

This setting has no default value.


``protocol``
~~~~~~~~~~~~
This setting decides which protocol to use. It must be one of:

``udp``
   Regular UDP DNS. Defaults to port 53.

``tcp``
   Regular TCP DNS. Defaults to port 53.

``udptcp``
   Regular UDP DNS with fallback to TCP. Defaults to port 53.

``dot``
   DNS-over-TLS. Defaults to port 853.

``doh``
   DNS-over-HTTPS. Defaults to port 443.

``doq``
   DNS-over-QUIC. Defaults to port 443.

The default value is ``udp``.


``query_class``
~~~~~~~~~~~~~~~
This setting decides the query class to use in the outgoing DNS query. Class ``IN`` and ``CHAOS`` are supported.

The default value is ``IN``.


``query_name``
~~~~~~~~~~~~~~
This setting decides the DNS name to use in the outgoing DNS query.

This setting has no default value.


``query_type``
~~~~~~~~~~~~~~
This setting decides the query type to use in the outgoing DNS query. Most types are supported and it is possible to use ``TYPE1`` instead of ``A`` if a specific type is not supported.

The default value is ``A``.


``recursion_desired``
~~~~~~~~~~~~~~~~~~~~~
This bool decides whether or not to enable the ``RD`` flag in the outgoing DNS query.

The default value is ``True``.


``server``
~~~~~~~~~~
This setting configures the DNS server to send the outgoing DNS query to. Many formats are supported:

* v4 IP
* v6 IP
* v4ip:port
* v6ip:port
* hostname
* hostname:port
* https:// url with IP or hostname, with or without port, with or without path

Depending on the ``protocol`` of course. Hostnames will be resolved (either as ``A`` or ``AAAA`` depending on the ``family`` setting).


``timeout``
~~~~~~~~~~~
This setting configures the timeout in seconds. The exporter will wait this long for a response from the DNS server. If a response isn't received before the timeout the query is considered failed.

The default value is ``5.0``.


``validate_answer_rrs``
~~~~~~~~~~~~~~~~~~~~~~~
This setting defines validation rules for the ``ANSWER`` section of the DNS response. ``validate_answer_rrs`` can do the following validations:

``fail_if_matches_regexp``
   A list of regular expressions. Each RR in the ``ANSWER`` section is checked against each regular expression in the list. The query is considered failed if a match is found.

``fail_if_all_match_regexp``
   A list of regular expressions. Each RR in the ``ANSWER`` section is checked against each regular expression in the list. The query is considered failed if an RR match all regular expressions in the list.
   
``fail_if_not_matches_regexp``
   A list of regular expressions. Each RR in the ``ANSWER`` section is checked against each regular expression in the list. The query is considered failed if a nonmatch is found.

``fail_if_none_matches_regexp``
   A list of regular expressions. Each RR in the ``ANSWER`` section is checked against each regular expression in the list. The query is considered failed if no matches are found.
   
``fail_if_count_eq``
   An integer. The query is considered failed if the RR count in the ``ANSWER`` section equals this number.

``fail_if_count_ne``
   An integer. The query is considered failed if the RR count in the ``ANSWER`` section does not equal this number.

``fail_if_count_lt``
   An integer. The query is considered failed if the RR count in the ``ANSWER`` section is less than this number.

``fail_if_count_gt``
   An integer. The query is considered failed if the RR count in the ``ANSWER`` section is bigger than this number.

This setting has no default value.

.. Note:: The ``validate_answer_rrs`` setting can only be configured in a module in a config file. It can not be set in the scrape request querystring.


``validate_authority_rrs``
~~~~~~~~~~~~~~~~~~~~~~~~~~
This setting defines validation rules for the ``AUTHORITY`` section of the DNS response. ``validate_authority_rrs`` can do the same validations as ``validate_answer_rrs``, see above for details.

This setting has no default value.

.. Note:: The ``validate_authority_rrs`` setting can only be configured in a module in a config file. It can not be set in the scrape request querystring.

``validate_additional_rrs``
~~~~~~~~~~~~~~~~~~~~~~~~~~~
This setting defines validation rules for the ``ADDITIONAL`` section of the DNS response. ``validate_additional_rrs`` can do the same validations as ``validate_answer_rrs``, see above for details.

This setting has no default value.

.. Note:: The ``validate_additional_rrs`` setting can only be configured in a module in a config file. It can not be set in the scrape request querystring.

``validate_response_flags``
~~~~~~~~~~~~~~~~~~~~~~~~~~~
This setting can be used to validate the response flags of the DNS response. ``validate_response_flags`` can do the following validations:

``fail_if_any_present``
   A list of response flags. The query is considered failed if *any of the flags are present* in the response.

``fail_if_all_present``
   A list of response flags. The query is considered failed if *all of the flags are present* in the response.

``fail_if_any_absent``
   A list of response flags. The query is considered failed if *any of the flags are absent* from the response.

``fail_if_all_absent``
   A list of response flags. The query is considered failed if *all of the flags are absent* from the response.

This setting has no default value.

.. Note:: The ``validate_response_flags`` setting can only be configured in a module in a config file. It can not be set in the scrape request querystring.

``valid_rcodes``
~~~~~~~~~~~~~~~~
A comma seperated list of valid ``RCODE`` values. This setting defines the ``RCODE`` values to consider valid in the DNS response. The query is considered failed if the ``RCODE`` is not among the list in this setting.

The default value is ``NOERROR``.
