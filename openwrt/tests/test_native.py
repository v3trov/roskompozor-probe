"""Differential tests against the untouched Python reference, using local servers.
Python and the C binary see the same DNS/connect fixtures through LD_PRELOAD.
The test shim is separate and never shipped in the package.
"""
import contextlib
import http.server
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import random
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / 'openwrt/src/roskompozor-probe'
HARNESS = ROOT / 'openwrt/tests/harness'
SHIM = ROOT / 'openwrt/tests/netshim.so'
spec = importlib.util.spec_from_file_location('reference', ROOT / 'roskompozor_probe.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def clean(value):
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items() if k not in ('ms', 'total_ms', 'error')}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    requests = []
    slow_root = False

    def do_GET(self):
        self.requests.append((self.path, self.headers.get('Host'), self.headers.get('User-Agent')))
        if self.path == '/slow-headers' or self.slow_root:
            try:
                self.connection.sendall(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                for _ in range(60):
                    time.sleep(.1)
                    self.connection.sendall(b'x')
                self.connection.sendall(b'\r\n\r\n')
            except (OSError, ssl.SSLError):
                pass
            return
        if self.path == '/redirect':
            code, location = 302, '/forbidden'
        elif self.path == '/loop':
            code, location = 301, '/loop'
        elif self.path == '/private':
            code, location = 302, 'http://127.0.0.1/'
        elif self.path == '/mixed':
            code, location = 302, 'http://mixed.example/'
        elif self.path == '/forbidden':
            code, location = 403, None
        else:
            code, location = 200, None
        self.send_response(code)
        if location:
            self.send_header('Location', location)
        self.send_header('Content-Length', '5000000')
        self.end_headers()  # No body: both probes must stop after headers.

    def log_message(self, *args):
        pass


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.tmp.name)
        cls.env = dict(os.environ, LD_PRELOAD=str(SHIM), FIXTURE_DNS='1.1.1.1')
        ca = cls.directory / 'ca.pem'
        key = cls.directory / 'key.pem'
        cert = cls.directory / 'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(ca), '-days', '2', '-subj', '/CN=Probe Fixture CA'], check=True, capture_output=True)
        csr = cls.directory / 'csr.pem'
        subprocess.run(['openssl', 'req', '-new', '-key', str(key), '-out', str(csr), '-subj', '/CN=example.com'], check=True, capture_output=True)
        ext = cls.directory / 'ext.cnf'
        ext.write_text('subjectAltName=DNS:example.com\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
        subprocess.run(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(key), '-CAcreateserial', '-out', str(cert), '-days', '1', '-extfile', str(ext)], check=True, capture_output=True)
        cls.env['SSL_CERT_FILE'] = str(ca)
        ping = cls.directory / 'ping'
        ping.write_text('#!/bin/sh\ncase "$*" in *1.1.1.1*) echo "64 bytes: time=1.4 ms"; exit 0;; *) exit 1;; esac\n')
        ping.chmod(0o755)
        cls.env['PATH'] = str(cls.directory) + ':' + cls.env['PATH']
        cls.servers = []
        ports = []
        for tls in (False, True):
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            server.daemon_threads = True
            if tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert, key)
                server.socket = ctx.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.servers.append(server)
            ports.append(server.server_port)
        cls.env['FIXTURE_PORTS'] = f'80:{ports[0]},443:{ports[1]},1380:{ports[0]}'

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        cls.tmp.cleanup()

    def native(self, mode, *args, env=None):
        process = subprocess.run([str(HARNESS), mode, *map(str, args)], env=env or self.env, capture_output=True, text=True, timeout=30, check=True)
        return json.loads(process.stdout)

    def python(self, expression, env=None):
        code = f'import json,sys; sys.path.insert(0,{str(ROOT)!r}); import roskompozor_probe as p; print(json.dumps({expression},ensure_ascii=False))'
        process = subprocess.run([sys.executable, '-c', code], env=env or self.env, capture_output=True, text=True, timeout=30, check=True)
        return json.loads(process.stdout)

    def check_pair(self, item, env=None):
        path = self.directory / 'check.json'
        path.write_text(json.dumps(item))
        process = subprocess.run([str(NATIVE), '--check', str(path)], env=env or self.env, capture_output=True, text=True, timeout=30, check=True)
        native = json.loads(process.stdout)
        expected = self.python(f'p.run_check({item!r},10)', env=env)
        self.assertEqual(clean(native), clean(expected))
        return native

    def test_public_policy(self):
        values = ['0.0.0.0', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.169.254', '172.16.0.1', '192.0.0.8', '192.0.0.9', '192.0.0.10', '192.0.0.11', '192.0.2.1', '192.168.1.1', '198.18.0.1', '203.0.113.1', '224.0.0.1', '240.0.0.1', '1.1.1.1', '8.8.8.8', '::', '::1', '::ffff:1.1.1.1', '64:ff9b::808:808', '2001::1', '2001:1::1', '2001:1::3', '2001:3::1', '2001:4:112::1', '2001:20::1', '2001:30::1', '2001:db8::1', '2002::1', '2606:4700:4700::1111', 'fc00::1', 'fe80::1', 'ff00::1']
        rng = random.Random(37)
        values += [str(ipaddress.ip_address(rng.getrandbits(bits))) for bits in (32, 128) for _ in range(60)]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(self.native('public', value), reference.public_ip(value))

    def test_idna_normalization(self):
        for raw in ['EXAMPLE.COM.', ' пример.рф. ', 'faß.de', 'bücher.example', '2001:4860:4860::8888', '1.1.1.1', 'localhost', 'a..b', '-bad.com', 'bad-.com', 'a' * 64 + '.com', 'http://example.com', '123.999.1.1']:
            with self.subTest(raw=raw):
                try:
                    expected = reference.normalize_host(raw)
                except (ValueError, UnicodeError):
                    self.assertIn('error', self.native('normalize', raw))
                else:
                    self.assertEqual(self.native('normalize', raw), {'host': expected})

    def test_url_parser(self):
        for url in ['http://example.com', 'https://EXAMPLE.com/test?q=x#fragment', 'http://[2606:4700::1111]/', 'http://example.com:443/', 'https://example.com:80/', 'http://example.com:0/', 'http://example.com:1380/', 'ftp://example.com/', 'http://user:pass@example.com/', 'http://example.com/?x=%20', 'https://пример.рф/', 'http://example.com/a/../b']:
            with self.subTest(url=url):
                try:
                    scheme, host, port, path = reference.parse_url(url)
                except ValueError:
                    self.assertIn('error', self.native('url', url))
                else:
                    self.assertEqual(self.native('url', url), dict(scheme=scheme, host=host, port=port, path=path))

    def test_dns_all_answers_and_sorting(self):
        for answers in ['8.8.8.8,1.1.1.1,9.9.9.9,8.8.4.4,4.2.2.2,1.1.1.1', '1.1.1.1,127.0.0.1', '1.1.1.1,8.8.8.8,9.9.9.9,4.2.2.2,8.8.4.4,10.0.0.1', 'FAIL', '2606:4700:4700::1111,1.1.1.1']:
            env = dict(self.env, FIXTURE_DNS=answers)
            result = self.native('resolve', 'example.com', env=env)
            if answers == 'FAIL' or '127.' in answers or '10.0.' in answers:
                self.assertIn('error', result)
            else:
                self.assertEqual(result['addresses'], self.python("p.resolve_public('example.com')", env=env))

    def test_invalid_jobs(self):
        for item in [dict(target='1.1.1.1', type='ip', ports=[port]) for port in [True, 0, 65536, '443', 2.5]] + [dict(target='1.1.1.1', type='domain'), dict(target='example.com', type='domain', ports=list(range(1, 10))), dict(target='example.com', type='domain', ports=None)]:
            with self.subTest(item=item):
                self.check_pair(item)

    def test_full_success(self):
        result = self.check_pair(dict(target='example.com', type='domain', ports=[80, 443, 1380, 1380, 9999]))
        self.assertTrue(result['ok'])
        self.assertEqual(list(result['tcp']), ['80', '443', '1380', '9999'])
        self.assertFalse(result['tcp']['9999']['ok'])
        self.assertTrue(result['tls']['ok'])
        self.assertEqual(result['tls']['subject'], 'example.com')

    def test_full_closed(self):
        env = dict(self.env, FIXTURE_PORTS='none', FIXTURE_DNS='8.8.8.8')
        result = self.check_pair(dict(target='example.com', type='domain', ports=[]), env=env)
        self.assertFalse(result['ok'])
        self.assertEqual(result['tls']['attempts'], [])

    def test_timeout_and_reset(self):
        for code, category in [(-1, 'timeout'), (-2, 'connection reset')]:
            env = dict(self.env, FIXTURE_PORTS=f'80:{code},443:{code}', FIXTURE_DNS='8.8.8.8')
            with self.subTest(category=category):
                result = self.check_pair(dict(target='example.com', type='domain'), env=env)
                self.assertFalse(result['ok'])
                self.assertEqual(result['tcp']['80']['error_type'], category)
                self.assertEqual(result['http']['error_type'], category)

    def test_missing_ping_and_dns_failure(self):
        result = self.check_pair(dict(target='example.com', type='domain'), env=dict(self.env, PATH='/nonexistent'))
        self.assertEqual(result['ping']['error_type'], 'unavailable')
        self.assertTrue(result['ok'])
        result = self.check_pair(dict(target='example.com', type='domain'), env=dict(self.env, FIXTURE_DNS='FAIL'))
        self.assertEqual(result['error_type'], 'DNS error')
        self.assertNotIn('tcp', result)

    def test_attempt_order_and_ping_all(self):
        env = dict(self.env, FIXTURE_DNS='8.8.8.8,1.1.1.1,2606:4700:4700::1111')
        result = self.check_pair(dict(target='example.com', type='domain'), env=env)
        self.assertEqual(len(result['ping']['attempts']), 3)
        self.assertEqual(len(result['tcp']['80']['attempts']), 1)

    def test_packaged_binary_slow_headers_deadline(self):
        Handler.slow_root=True
        try:
            started=time.monotonic()
            actual=self.check_pair(dict(target='example.com',type='domain'))
            self.assertLess(time.monotonic()-started,10)
            for protocol in ['http','https']:
                self.assertFalse(actual[protocol]['ok'])
                self.assertEqual(actual[protocol]['error_type'],'timeout')
        finally:
            Handler.slow_root=False

    def test_slow_headers_share_operation_deadline(self):
        for scheme in ['http', 'https']:
            url=scheme+'://example.com/slow-headers'
            started=time.monotonic()
            actual=self.native('chain',url)
            self.assertLess(time.monotonic()-started,4.5)
            self.assertFalse(actual['ok'])
            self.assertEqual(actual['error_type'],'timeout')
            expected=self.python(f'p.http_chain({url!r},2)')
            self.assertEqual(clean(actual),clean(expected))

    def test_http_status_redirect_and_limit(self):
        for path in ['/forbidden', '/redirect', '/loop', '/private']:
            url = 'http://example.com' + path
            with self.subTest(path=path):
                native = self.native('chain', url)
                try:
                    expected = self.python(f'p.http_chain({url!r},2)')
                except subprocess.CalledProcessError:
                    self.assertIn('error', native)
                else:
                    self.assertEqual(clean(native), clean(expected))
                    if path == '/loop':
                        self.assertEqual(len(native['chain']), 6)
                    if path == '/forbidden':
                        self.assertTrue(native['ok'])
                        self.assertEqual(native['status'], 403)

    def test_certificate_hostname_failure(self):
        native = self.native('tls', 'wrong.example.com')
        expected = self.python("p.tls_check('wrong.example.com',['1.1.1.1'],2)")
        self.assertEqual(clean(native), clean(expected))
        self.assertEqual(native['error_type'], 'TLS error')

    def test_url_join(self):
        base = 'http://example.com/a/b?old=x'
        for location in ['/x', '../c?q=y', '?new=z', '//other.example/test', 'https://example.com/y', '#frag']:
            with self.subTest(location=location):
                self.assertEqual(self.native('join', base, location)['url'], urllib.parse.urljoin(base, location))

    def test_config_limits(self):
        path = self.directory / 'config.json'
        config = dict(server='https://roskompozor.ru/', api_key='x' * 68, poll_interval=1, request_timeout=100, max_parallel_checks=100)
        path.write_text(json.dumps(config))
        actual = self.native('config', path)
        expected = reference.load_config(path)
        expected.pop('api_key')
        expected['server'] = expected['server'].rstrip('/')
        self.assertEqual(actual, expected)
        for server in ['file:///etc/passwd', 'https://user:pass@example.com']:
            config['server'] = server
            path.write_text(json.dumps(config))
            self.assertIn('error', self.native('config', path))

    def test_api_roundtrip_and_parallel_checks(self):
        captured = []
        jobs = [dict(id=str(i), target='example.com', type='domain', ports=[1380]) for i in range(3)]

        class Api(http.server.BaseHTTPRequestHandler):
            def respond(self, data):
                encoded = json.dumps(data).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def do_GET(self):
                captured.append((self.path, self.headers.get('Authorization')))
                self.respond({'checks': jobs})

            def do_POST(self):
                captured.append((self.path, self.headers.get('Authorization')))
                captured.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                self.respond(dict(accepted=3, duplicates=0, rejected=0))

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Api)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            key = 'fixture_key_' + '0' * 64
            config = dict(server=f'http://127.0.0.1:{server.server_port}', api_key=key, poll_interval=5, request_timeout=10, max_parallel_checks=2)
            path = self.directory / 'api.json'
            path.write_text(json.dumps(config))
            env = dict(self.env, FIXTURE_PORTS=self.env['FIXTURE_PORTS'] + f',{server.server_port}:{server.server_port}')
            process = subprocess.run([str(NATIVE), '--once', str(path)], env=env, capture_output=True, text=True, timeout=30, check=True)
            self.assertIn('accepted=3', process.stderr)
            self.assertNotIn(key, process.stderr + process.stdout)
            self.assertEqual(captured[0], ('/api/probe/checks', 'Bearer ' + key))
            self.assertEqual(captured[1], ('/api/probe/results', 'Bearer ' + key))
            self.assertEqual([r['check_id'] for r in captured[2]['results']], ['0', '1', '2'])
            self.assertTrue(all(r['result']['ok'] for r in captured[2]['results']))
            captured.clear()
            config.update(server=f'http://fixture-api.invalid:{server.server_port}', api_connect_ip='127.0.0.1')
            path.write_text(json.dumps(config))
            process = subprocess.run([str(NATIVE), '--once', str(path)], env=env, capture_output=True, text=True, timeout=30, check=True)
            self.assertIn('accepted=3', process.stderr)
            self.assertNotIn(key, process.stderr + process.stdout)
            self.assertEqual(captured[0], ('/api/probe/checks', 'Bearer ' + key))
            config['api_connect_ip'] = '127.0.0.1,example.com'
            path.write_text(json.dumps(config))
            process = subprocess.run([str(NATIVE), '--validate-config', str(path)], env=env, capture_output=True, text=True)
            self.assertNotEqual(process.returncode, 0)
        finally:
            server.shutdown()
            server.server_close()

    def test_atomic_config_helper(self):
        directory = self.directory / 'helper-settings'
        directory.mkdir(exist_ok=True)
        script = (ROOT / 'luci-app-roskompozor-probe/files/config-helper').read_text()
        script = script.replace('/etc/roskompozor-probe', str(directory))
        script = script.replace('/var/lock', str(self.directory))
        script = script.replace('/usr/bin/roskompozor-probe', str(NATIVE))
        helper = self.directory / 'config-helper'
        helper.write_text(script)
        current = directory / 'config.json'
        pending = directory / 'config.pending'
        previous = directory / 'config.previous'
        current.write_text('original config')
        current.chmod(0o600)
        pending.write_text('invalid JSON')
        failed = subprocess.run(['sh', str(helper), 'save'], capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(current.read_text(), 'original config')
        self.assertFalse(previous.exists())
        config = dict(server='https://roskompozor.ru', api_key='rkp_' + 'a' * 64, poll_interval=10, request_timeout=10, max_parallel_checks=1)
        pending.write_text(json.dumps(config))
        subprocess.run(['sh', str(helper), 'save'], capture_output=True, check=True)
        self.assertEqual(json.loads(current.read_text()), config)
        self.assertEqual(previous.read_text(), 'original config')
        self.assertEqual(current.stat().st_mode & 0o777, 0o600)
        self.assertEqual(previous.stat().st_mode & 0o777, 0o600)
        self.assertFalse(pending.exists())
        pending.symlink_to(current)
        try:
            failed = subprocess.run(['sh', str(helper), 'save'], capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(json.loads(current.read_text()), config)
        finally:
            pending.unlink()


if __name__ == '__main__':
    unittest.main()
