import unittest
from unittest.mock import patch
import roskompozor_probe as probe

class DeadlineTests(unittest.TestCase):
    def test_slow_headers_cannot_renew_operation_timeout(self):
        elapsed=[0.0]
        class Peer:
            closed=False
            timeout=0
            def settimeout(self,value):self.timeout=value
            def sendall(self,data):pass
            def recv(self,size):
                if self.timeout<1:
                    elapsed[0]+=self.timeout
                    raise TimeoutError('timeout')
                elapsed[0]+=1
                return b'H'
            def close(self):self.closed=True
        peer=Peer()
        with patch.object(probe.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(probe,'resolve_public',return_value=['8.8.8.8']),patch.object(probe.socket,'create_connection',return_value=peer):
            result=probe.http_once('http://example.org/',3)
        self.assertFalse(result['ok']);self.assertEqual(result['error_type'],'timeout');self.assertLessEqual(elapsed[0],3);self.assertTrue(peer.closed)

    def test_normal_headers_and_redirect_contract_unchanged(self):
        class Peer:
            def settimeout(self,value):pass
            def sendall(self,data):pass
            def recv(self,size):return b'HTTP/1.1 302 Found\r\nLocation: /next\r\n\r\n'
            def close(self):pass
        with patch.object(probe,'resolve_public',return_value=['8.8.8.8']),patch.object(probe.socket,'create_connection',return_value=Peer()):
            result=probe.http_once('http://example.org/',3)
        self.assertTrue(result['ok']);self.assertEqual(result['status'],302);self.assertEqual(result['location'],'/next')

    def test_mixed_private_dns_still_rejected_before_selection(self):
        answers=[(2,1,6,'',('8.8.8.8',0))]*4+[(2,1,6,'',('127.0.0.1',0))]
        with patch.object(probe.socket,'getaddrinfo',return_value=answers):
            with self.assertRaises(ValueError):probe.resolve_public('example.org')

if __name__=='__main__':unittest.main()
