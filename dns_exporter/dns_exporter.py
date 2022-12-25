"""dns_exporter is a blackbox-style Prometheus exporter for DNS."""
import ipaddress
import logging
import random
import time
import urllib.parse
from http.server import HTTPServer

import dns.edns
import dns.exception
import dns.opcode
import dns.query
import dns.rcode
import dns.resolver
from prometheus_client import Counter, Histogram, MetricsHandler

logger = logging.getLogger(__name__)

QUERIES = Counter("dns_queries_total", "DNS queries total.")
QTIME = Histogram(
    "dns_query_time_seconds",
    "DNS query time in seconds.",
    ["server", "protocol", "qname", "qtype", "opcode", "rcode", "nsid", "ip"],
)


class DNSRequestHandler(MetricsHandler):
    """MetricsHandler class for incoming scrape requests."""

    def do_GET(self):
        """Handle incoming scrape requests."""
        # parse incoming request
        parsed_path = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed_path.query)

        # get protocol
        protocol = query["protocol"][0]
        if protocol not in ["udp", "tcp", "dot", "doh", "doq"]:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(
                "Unsupported protocol, use one of: udp, tcp, dot, doh, doq".encode(
                    "utf-8"
                )
            )
            return

        server = query["server"][0]
        # the server parameter can be an IP, or a hostname, or a URL
        try:
            ipaddress.ip_address(server)
            ip = server
        except ValueError:
            # not an IP, is this a url or a hostname?
            parsed_server = urllib.parse.urlsplit(server)
            if parsed_server.scheme == "" and parsed_server.netloc == "":
                # this looks like a hostname, resolve it and pick an ip
                res = dns.resolver.Resolver()
                ans = None
                if query["family"][0] == "v4":
                    ans = res.resolve(server, "A")
                elif query["family"][0] == "v6":
                    ans = res.resolve(server, "AAAA")
                # did we get an answer?
                if ans is None:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(
                        "Unsupported address family, use one of: v4, v6".encode("utf-8")
                    )
                    return

                # pick a random IP
                if ans:
                    ip = random.choice(ans)
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write("Invalid server".encode("utf-8"))
                    return

                if protocol == "doh":
                    # create url for DoH
                    server = f"https://{server}/dns-query"

        if not isinstance(ip, str):
            ip = str(ip)
        logger.debug(f"using server {server} and ip {ip} for dns lookup...")
        qname = dns.name.from_text(query["qname"][0])
        q = dns.message.make_query(qname=qname, rdtype=query["qtype"][0])
        q.use_edns(payload=4096, options=[dns.edns.GenericOption(dns.edns.NSID, "")])

        qargs = {"timeout": 5}

        try:
            start = time.time()
            if protocol == "udp":
                logger.warning(
                    f"doing UDP lookup with ip {ip} and server {server} and qname {qname}"
                )
                r = dns.query.udp(q, ip, **qargs)
            elif protocol == "tcp":
                logger.warning(
                    f"doing TCP lookup with ip {ip} and server {server} and qname {qname}"
                )
                r = dns.query.tcp(q, ip, **qargs)
            elif protocol == "dot":
                logger.warning(
                    f"doing DoT lookup with ip {ip} and server {server} and qname {qname}"
                )
                r = dns.query.tls(q, ip, server_hostname=server, **qargs)
            elif protocol == "doh":
                logger.warning(
                    f"doing DoH lookup with ip {ip} and server {server} and qname {qname}"
                )
                # https://github.com/rthalley/dnspython/issues/875
                # r = dns.query.https(q=q, where=server, bootstrap_address=ip, **qargs)
                r = dns.query.https(q=q, where=server, **qargs)
            elif protocol == "doq":
                logger.warning(
                    f"doing DoQ lookup with ip {ip} and server {server} and qname {qname}"
                )
                r = dns.query.quic(q, ip, **qargs)
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(
                    "Unsupported protocol, use one of: udp, tcp, dot, doh, doq".encode(
                        "utf-8"
                    )
                )
                return
        except dns.exception.DNSException as E:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"DNS lookup failed with exception: {E}".encode("utf-8"))
            return

        qtime = time.time() - start
        QUERIES.inc()

        nsid = ""
        for opt in r.options:
            if opt.otype == dns.edns.NSID:
                # treat as ascii, we need text for prom labels
                nsid = opt.data.decode("ASCII")
        QTIME.labels(
            server=query["server"][0],
            protocol=query["protocol"][0],
            qname=query["qname"][0],
            qtype=query["qtype"][0],
            opcode=dns.opcode.to_text(r.opcode()),
            rcode=dns.rcode.to_text(r.rcode()),
            nsid=nsid,
            ip=ip,
        ).observe(qtime)
        return super(DNSRequestHandler, self).do_GET()


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 15353), DNSRequestHandler).serve_forever()
