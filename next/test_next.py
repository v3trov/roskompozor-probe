import json
import socket
import ssl
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import network as net
import probe_next as runner


class NetworkTests(unittest.TestCase):
    def test_private_targets_never_open_a_socket(self):
        with patch.object(net.socket, 'socket') as create:
            for ip in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', '::ffff:127.0.0.1'):
                with self.assertRaises(ValueError):
                    net.connect_public(ip, 443, time.monotonic() + 1)
            create.assert_not_called()

    def test_mixed_system_dns_rejects_every_address(self):
        result = type('Reply', (), {'stdout': '["1.1.1.1","10.0.0.1"]'})()
        with patch.object(net.subprocess, 'run', return_value=result):
            self.assertEqual(net.system_dns('example.org'),
                {'ok': False, 'error_type': 'non_public_answer', 'addresses': []})

    def test_system_dns_has_a_killable_deadline(self):
        with patch.object(net.subprocess, 'run', side_effect=net.subprocess.TimeoutExpired('dns', 4)):
            self.assertEqual(net.system_dns('example.org')['error_type'], 'timeout')

    def test_direct_dns_supports_resolution_without_a_service_port(self):
        with patch.object(net, 'direct_addresses', return_value=['1.1.1.1', '2606:4700:4700::1111']):
            answers = net.direct_getaddrinfo('example.org', None, type=net.socket.SOCK_STREAM)
        self.assertEqual(answers[0][4], ('1.1.1.1', 0))
        self.assertEqual(answers[1][4], ('2606:4700:4700::1111', 0, 0, 0))

    def answer(self, rcode=0):
        ident, query = net.dns_packet('example.org', 1)
        header = struct.pack('!6H', ident, 0x8180 | rcode, 1, 1 if not rcode else 0, 0, 0)
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('1.1.1.1')
        return ident, header + query[12:] + (answer if not rcode else b'')

    def test_dns_compression_and_answer(self):
        ident, reply = self.answer()
        self.assertEqual(net.parse_dns(reply, ident, 'example.org', 1)['addresses'], ['1.1.1.1'])

    def test_dns_wrong_id_or_question_rejected(self):
        ident, reply = self.answer()
        for expected, host, kind in ((ident ^ 1, 'example.org', 1), (ident, 'different.org', 1), (ident, 'example.org', 28)):
            with self.assertRaises(ValueError):
                net.parse_dns(reply, expected, host, kind)

    def test_dns_nxdomain_is_an_observation(self):
        ident, reply = self.answer(3)
        result = net.parse_dns(reply, ident, 'example.org', 1)
        self.assertTrue(result['ok'])
        self.assertEqual(result['rcode'], 3)
        self.assertNotIn('blocked', result)

    def test_dns_pointer_loop_and_truncation_rejected(self):
        for data in (b'\xc0\x00', b'\xc0', b'\x03ab'):
            with self.assertRaises(ValueError):
                net.dns_name(data, 0)

    def test_dns_different_cdn_ips_do_not_prove_spoofing(self):
        def query(resolver, protocol, host, kind):
            return {'provider': resolver[0], 'protocol': protocol, 'record': 'A' if kind == 1 else 'AAAA',
                    'ok': True, 'rcode': 0, 'truncated': False,
                    'addresses': ['1.1.1.1' if protocol == 'doh' else '8.8.8.8']}
        with patch.object(net, 'dns_query', side_effect=query):
            result = net.compare_dns('example.org')
        self.assertTrue(result['differences'])
        self.assertFalse(result['spoofing_proven'])

    def test_failed_dns_observations_mean_insufficient_data(self):
        def query(resolver, protocol, host, kind):
            return {'provider': resolver[0], 'protocol': protocol, 'record': 'A' if kind == 1 else 'AAAA', 'ok': False}
        with patch.object(net, 'dns_query', side_effect=query):
            result = net.compare_dns('example.org')
        self.assertEqual(result['interpretation'], 'insufficient_data')

    def test_unavailable_control_cannot_support_sni_conclusion(self):
        with patch.object(net, 'control_attempt', side_effect=[{'ok': False}, {'ok': False}, {'ok': False}]):
            result = net.sni_controls('example.org', [{'id': 'eu', 'ip': '1.1.1.1'}])[0]
        self.assertEqual(result['interpretation'], 'control_unavailable')
        self.assertFalse(result['blocking_proven'])

    def test_sni_difference_requires_two_successful_baselines(self):
        for sequence, expected in (([True, False, True], 'target_sni_difference'),
                                    ([True, False, False], 'control_unavailable'),
                                    ([True, True, True], 'no_difference_observed')):
            with patch.object(net, 'control_attempt', side_effect=[{'ok': v} for v in sequence]):
                result = net.sni_controls('example.org', [{'id': 'test', 'ip': '1.1.1.1'}])[0]
            self.assertEqual(result['interpretation'], expected)

    def test_private_control_and_invalid_target_rejected(self):
        for target, controls in (({'target': '127.0.0.1', 'type': 'ip'}, []),
                                 ({'target': 'example.org', 'type': 'domain'}, [{'id': 'x', 'ip': '10.0.0.1'}])):
            with self.assertRaises(ValueError):
                net.measure(target, controls)

    def test_family_missing_address_is_unknown(self):
        result = net.family_measurements('example.org', [])
        self.assertEqual(result['ipv4']['status'], 'no_address')
        self.assertEqual(result['ipv6']['status'], 'no_address')

    def test_dns_failure_does_not_imply_absent_ipv6_record(self):
        result = net.family_measurements('example.org', [], dns_ok=False)
        self.assertEqual(result['ipv6']['status'], 'dns_unavailable')

    def test_unconfigured_sni_is_skipped_before_network(self):
        with patch.object(net, 'control_attempt') as attempt:
            result = net.sni_controls('other.org', [{'id': 'scoped', 'scope': ['example.org']}])[0]
        attempt.assert_not_called()
        self.assertEqual(result['interpretation'], 'outside_control_scope')

    def test_family_success_does_not_hide_other_family_failure(self):
        with patch.object(net.legacy, 'tcp_check', side_effect=lambda ip, *_: {'ok': ':' not in ip}), \
             patch.object(net, 'tls_attempt', side_effect=lambda host, ip, *_: {'ok': ':' not in ip}):
            result = net.family_measurements('example.org', ['1.1.1.1', '2606:4700:4700::1111'])
        self.assertTrue(result['ipv4']['attempts'][0]['tcp443']['ok'])
        self.assertFalse(result['ipv6']['attempts'][0]['tcp443']['ok'])

    def test_tls_certificate_error_kept_separate(self):
        class Stream:
            def settimeout(self, value): pass
            def close(self): pass
        with patch.object(net, 'connect_public', return_value=Stream()), \
             patch.object(net.ssl.SSLContext, 'wrap_socket', side_effect=ssl.SSLCertVerificationError('expired')):
            result = net.tls_attempt('example.org', '1.1.1.1', True)
        self.assertTrue(result['certificate_error'])
        self.assertEqual(result['stage'], 'tls')

    def test_slow_body_cannot_reset_deadline_and_keeps_count(self):
        clock = [0.0]
        class Stream:
            calls = 0
            def settimeout(self, value): self.timeout = value
            def recv(self, size):
                self.calls += 1
                if self.calls == 1:
                    return b'HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\nx'
                clock[0] += 1
                return b'x'
        with patch.object(net.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(net.IncompletePayload) as caught:
                net.read_http(Stream(), 3, 65536)
        self.assertEqual(caught.exception.received, 4)
        self.assertEqual(caught.exception.reason, 'timeout')

    def test_control_body_is_bounded(self):
        class Stream:
            def settimeout(self, value): pass
            def recv(self, size): return b'HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n'
        with self.assertRaises(ValueError):
            net.read_http(Stream(), time.monotonic() + 2, 65536)


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'queue.sqlite'
        self.queue = runner.Queue(self.path)
        self.item = {'id': '42', 'target': 'example.org', 'type': 'domain', 'ports': []}

    def tearDown(self):
        self.queue.db.close()
        self.tmp.cleanup()

    def test_failed_submission_survives_restart(self):
        self.queue.add([self.item]); self.queue.next(1)
        self.queue.finish('42', {'ok': True})
        class Offline:
            def request(self, *args): raise OSError('offline')
        with self.assertRaises(OSError): self.queue.submit(Offline())
        self.queue.db.close(); self.queue = runner.Queue(self.path)
        self.assertEqual(self.queue.db.execute('SELECT state FROM jobs').fetchone()[0], 'outbox')
        class Accepted:
            def request(self, *args): return {'accepted': 0, 'duplicates': 1, 'rejected': 0}
        self.queue.submit(Accepted())
        self.assertEqual(self.queue.pending(), 0)

    def test_invalid_acknowledgement_retains_report(self):
        self.queue.add([self.item]); self.queue.finish('42', {'ok': True})
        class Invalid:
            def request(self, *args): return {'accepted': True, 'duplicates': 0, 'rejected': 0}
        with self.assertRaises(ValueError): self.queue.submit(Invalid())
        self.assertEqual(self.queue.pending(), 1)

    def test_interrupted_job_recovered_without_duplicate_insert(self):
        self.queue.add([self.item]); self.queue.next(1)
        self.queue.db.close(); self.queue = runner.Queue(self.path)
        self.queue.add([self.item])
        self.assertEqual(self.queue.next(2), [('42', self.item)])

    def test_pruning_preserves_unsent_results(self):
        self.queue.add([self.item]); self.queue.finish('42', {'ok': True})
        with self.queue.db: self.queue.db.execute('UPDATE jobs SET created=0')
        self.queue.prune()
        self.assertEqual(self.queue.pending(), 1)

    def test_untrusted_api_origin_rejected(self):
        for origin in ('http://example.org', 'https://u:p@example.org', 'https://example.org/?token=x'):
            with self.assertRaises(ValueError): runner.Api({'server': origin, 'api_key': 'x'})

    def test_redirects_cannot_forward_bearer(self):
        self.assertIsNone(runner.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example/'))

    def test_hung_measurement_is_killed(self):
        result = runner.execute_job(self.item, [], timeout=0.001)
        self.assertEqual(result['error_type'], 'timeout')


if __name__ == '__main__':
    unittest.main()
