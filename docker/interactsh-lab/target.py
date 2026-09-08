"""Local blind-fetch target: only generated hosts below the fixture domain work.

This uses the real Interactsh DNS and HTTPS listeners. Docker does not provide
wildcard DNS, so this fixture explicitly resolves payloads against its local OAST
server and then opens TLS with the original hostname and the fixture CA.
"""
import http.client
import json
import socket
import ssl
import struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

REQUESTS = []


def callback(host):
    server_ip = socket.gethostbyname("oast.test")
    transaction = 1776
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in host.split(".")) + b"\0"
    query = struct.pack("!6H", transaction, 0x100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        dns.settimeout(3)
        dns.sendto(query, (server_ip, 53))
        reply, _ = dns.recvfrom(4096)
        if reply[:2] != struct.pack("!H", transaction):
            raise RuntimeError("unexpected DNS response")
    context = ssl.create_default_context(cafile="/lab/ca.pem")
    connection = http.client.HTTPSConnection(host, timeout=5, context=context)
    # Keep SNI and certificate hostname validation for the original payload.
    connection.sock = context.wrap_socket(socket.create_connection((server_ip, 443), timeout=5), server_hostname=host)
    try:
        connection.request("GET", "/blind-fixture-callback")
        connection.getresponse().read()
    finally:
        connection.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        REQUESTS.append(self.path)
        path = urlsplit(self.path)
        if path.path == "/requests":
            body = json.dumps(REQUESTS).encode()
        elif path.path == "/fetch":
            payload = urlsplit(parse_qs(path.query).get("url", [""])[0])
            if payload.scheme != "https" or not payload.hostname or not payload.hostname.endswith(".oast.test") or payload.port:
                self.send_error(400)
                return
            callback(payload.hostname)
            body = b"queued"
        else:
            body = b"real callback fixture"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
