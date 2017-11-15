ItcProxy
========

HTTP/HTTPS intercepting proxy which forwards intercepted connections to
an upstream proxy.

HTTPS connections are not decrypted (no MITM), instead they are forwarded
according to Server name (SNI) from Client hello packet.

*Note:* ItcProxy does not handle redirecting TCP connections by itself,
you can use features of your network hardware or OS, like *iptables* on
Linux (example provided below)

*Limitation:* As TLS Client Hello message contains only target server name
and not port number, all connections are assumed to go to standard HTTPS
port 443.


Locations
---------

The `project page`_ is hosted on Github.

If you find something wrong or know of a missing feature, please
`create an issue`_ on the project page. If you find that inconvenient or have
some security concerns, you could also contact me by come means described at
my `home page`_.

.. _project page:    https://github.com/beli-sk/itcproxy
.. _create an issue: https://github.com/beli-sk/itcproxy/issues
.. _home page:       https://beli.sk


Requirements
------------

* scapy-ssl_tls_

.. _scapy-ssl_tls: https://github.com/tintinweb/scapy-ssl_tls


Usage
-----

::
  
  usage: itcproxy.py [-h] [-l LISTEN] [-p PORT] [-t TLSPORT] [-V]
                     upstream_host upstream_port
  
  ItcProxy - HTTP(S) intercepting proxy
  
  positional arguments:
    upstream_host         Upstream HTTP proxy host
    upstream_port         Upstream HTTP proxy port
  
  optional arguments:
    -h, --help            show this help message and exit
    -l LISTEN, --listen LISTEN
                          Listening address (default: any)
    -p PORT, --port PORT  Listening HTTP port (default: disable)
    -t TLSPORT, --tlsport TLSPORT
                          Listening TLS port (default: disable)
    -V, --version         show program's version number and exit


Example
-------

To intercept HTTPS connections, first use e.g. *iptables* on Linux to redirect
outgoing TCP connections to port 443::
  
  iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443

And then start ItcProxy, listening for HTTPS connections on port 8443 and
forwarding to your upstream proxy (172.16.1.1:3128 in this example)::
  
  itcproxy.py -t 8443 172.16.1.1 3128


License
-------

Copyright 2017 Michal Belica <https://beli.sk>

::
  
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
      http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

A copy of the license can be found in the ``LICENSE`` file in the
distribution.

