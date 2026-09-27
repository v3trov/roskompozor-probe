import importlib.util
import pathlib
import unittest
from unittest.mock import patch

import roskompozor_probe as probe


class ProbeTests(unittest.TestCase):
    def test_private_targets_rejected(self):
        for address in ['127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254', '::1', 'fc00::1']:
            with self.subTest(address=address), self.assertRaises(ValueError):
                probe.resolve_public(address)

    def test_mixed_dns_rejected(self):
        with patch.object(probe.socket, 'getaddrinfo', return_value=[
            (2, 1, 6, '', ('1.1.1.1', 0)), (2, 1, 6, '', ('127.0.0.1', 0))
        ]), self.assertRaises(ValueError):
            probe.resolve_public('example.com')

    def test_missing_ping_is_technical_error(self):
        with patch.object(probe.shutil, 'which', return_value=None):
            self.assertEqual(probe.ping_check('1.1.1.1', 2)['error_type'], 'unavailable')

    def test_invalid_ports_rejected(self):
        for port in [True, 0, 65536, '443']:
            result = probe.run_check(dict(target='1.1.1.1', type='ip', ports=[port]), 2)
            self.assertFalse(result['ok'])
            self.assertIn('invalid port', result['error'])

    def test_embedded_source_matches(self):
        root = pathlib.Path(__file__).parent
        installer = (root / 'install.sh').read_bytes()
        embedded = installer.split(b"<<'PROBE_SOURCE'\n", 1)[1].split(b'\nPROBE_SOURCE\n', 1)[0]
        self.assertEqual(embedded, (root / 'roskompozor_probe.py').read_bytes())


if __name__ == '__main__':
    unittest.main()
