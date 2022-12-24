import urlparse
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
from SocketServer import ForkingMixIn

from prometheus_client import CONTENT_TYPE_LATEST

class ForkingHTTPServer(ForkingMixIn, HTTPServer):
    pass

class DnsExporterHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse.urlparse(self.path)
        if url.path == '/metrics':
            params = urlparse.parse_qs(url.query)
            required = ["server", "protocol", "qname", "qtype"]
            for req in required:
                    if req not in params or len(params) != 4:
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(f"Missing '{req}' from parameters")
                        return
            output = collect_dns(**params)
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(output)
        elif url.path == '/':
            self.send_response(200)
            self.end_headers()
            self.wfile.write("""<html>
            <head><title>DNS Exporter</title></head>
            <body>
            <h1>DNS Exporter</h1>
            <p>Visit <code>/metrics?dnsserver=192.0.2.53&protocol=dnsudp&query=example.com&type=A</code> to see metrics.</p>
            </body>
            </html>""")
        else:
            self.send_response(404)
            self.end_headers()


def start_http_server(config_path, port):
    handler = lambda *args, **kwargs: DnsExporterHandler(config_path, *args, **kwargs)
    server = ForkingHTTPServer(('', port), handler)
    server.serve_forever()


def collect_dns(server, protocol, qname, qtype):
    """Scrape a host and return prometheus text format for it"""
    start = time.time()
    metrics = {}

    class Collector():
        def collect(self):
            return metrics.values()
    registry = CollectorRegistry()
    registry.register(Collector())
    duration = Gauge('dns_scrape_duration_seconds', 'Time this DNS query took, in seconds', registry=registry)
    duration.set(time.time() - start)
    return generate_latest(registry)
