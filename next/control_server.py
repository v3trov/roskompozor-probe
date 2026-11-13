#!/usr/bin/env python3
"""Owned TLS control: a static bounded payload, no forwarding, no request logs."""
import argparse
import http.server
import socket
import socketserver
import ssl
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.path != '/probe-control/65536':
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', '65536')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(b'R' * 65536)
        self.close_connection = True

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, context, allowed):
        self.context = context
        self.allowed = set(allowed)
        self.rate = {}
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, Handler)

    def get_request(self):
        stream, address = self.socket.accept()
        if self.allowed and address[0] not in self.allowed:
            stream.close()
            raise ConnectionAbortedError('not a trial node')
        now = time.monotonic()
        tokens, stamp = self.rate.get(address[0], (12.0, now))
        tokens = min(12.0, tokens + (now - stamp) * 6)
        if len(self.rate) >= 1024 and address[0] not in self.rate:
            self.rate.pop(next(iter(self.rate)))
        self.rate[address[0]] = (max(0, tokens - 1), now)
        if tokens < 1:
            stream.close()
            raise ConnectionAbortedError('control rate limit')
        stream.settimeout(4)
        return stream, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            # Handshake inside the bounded worker, not the single accept loop.
            with self.context.wrap_socket(request, server_side=True) as secure:
                self.finish_request(secure, address)
        except (OSError, ssl.SSLError):
            pass
        finally:
            request.close()
            self.slots.release()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--bind', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--allow', action='append', default=[])
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    Server((args.bind, args.port), context, args.allow).serve_forever()
