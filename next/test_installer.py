import ast
import base64
import hashlib
import io
from pathlib import Path
import re
import tarfile
import unittest


class InstallerTests(unittest.TestCase):
    def test_embedded_bundle_matches_every_runtime_file(self):
        root=Path(__file__).resolve().parents[1]
        source=(root/'install.sh').read_text(encoding='utf-8')
        value=re.search(r'data=base64.b64decode\(([^\n]+)\)',source).group(1)
        data=base64.b64decode(ast.literal_eval(value))
        digest=re.search(r"hexdigest\(\)=='([a-f0-9]{64})'",source).group(1)
        self.assertEqual(hashlib.sha256(data).hexdigest(),digest)
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
            for member in archive:
                with self.subTest(file=member.name):
                    self.assertTrue(member.isfile())
                    self.assertNotIn('..',Path(member.name).parts)
                    self.assertEqual(archive.extractfile(member).read(),(root/member.name).read_bytes().replace(b'\r\n',b'\n'))
        self.assertIn('ROSKOMPOZOR_SOCKET_MARK', (root/'next/openwrt.init').read_text())


if __name__=='__main__':unittest.main()
