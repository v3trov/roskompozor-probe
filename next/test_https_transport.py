"""Real HTTPS pull/POST contract test. Uses a temporary CA and loopback server."""
import http.server
import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import probe_next as runner


@unittest.skipUnless(shutil.which('openssl'), 'openssl required for temporary TLS fixture')
class HttpsTransportTests(unittest.TestCase):
    def test_pull_durable_submission_duplicate_and_redirect_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
                '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem')],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            received, tokens = set(), []
            item = {'id': '1', 'target': 'example.org', 'type': 'domain', 'ports': []}
            redirect = [False]
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args): pass
                def reply(self, body):
                    data = json.dumps(body).encode()
                    self.send_response(200); self.send_header('Content-Length', str(len(data)))
                    self.end_headers(); self.wfile.write(data)
                def do_GET(self):
                    tokens.append(self.headers.get('Authorization'))
                    if redirect[0]:
                        self.send_response(302)
                        self.send_header('Location', '/forbidden')
                        self.end_headers()
                    elif self.path == '/api/probe/checks': self.reply({'checks': [item]})
                    else: self.send_error(500)
                def do_POST(self):
                    tokens.append(self.headers.get('Authorization'))
                    self.assert_path = self.path
                    body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    key = body['results'][0]['check_id']
                    duplicate = key in received
                    received.add(key)
                    self.reply({'accepted': 0 if duplicate else 1, 'duplicates': 1 if duplicate else 0, 'rejected': 0})
            server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / 'cert.pem', root / 'key.pem')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            queue = runner.Queue(root / 'queue.sqlite')
            try:
                api = runner.Api({'server': f'https://127.0.0.1:{server.server_port}', 'api_key': 'fixture-token'})
                trusted = ssl.create_default_context(cafile=str(root / 'cert.pem'))
                api.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                    runner.NoRedirect(), urllib.request.HTTPSHandler(context=trusted))
                queue.add(api.request('/api/probe/checks')['checks'])
                self.assertEqual(queue.next(1), [('1', item)])
                queue.finish('1', {'ok': True})
                # First POST reaches the server, but the client loses the acknowledgement.
                api.request('/api/probe/results', {'results': [{'check_id': '1', 'result': {'ok': True}}]})
                queue.db.close(); queue = runner.Queue(root / 'queue.sqlite')
                queue.submit(api)
                self.assertEqual(queue.pending(), 0)
                self.assertEqual(len(tokens), 3)
                self.assertTrue(all(t == 'Bearer fixture-token' for t in tokens))
                redirect[0] = True
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    api.request('/api/probe/checks')
                self.assertEqual(raised.exception.code, 302)
                self.assertEqual(len(tokens), 4)  # The redirected URL never receives a request.
            finally:
                queue.db.close()
                server.shutdown(); server.server_close(); thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
