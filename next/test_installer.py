import ast
import base64
import hashlib
import io
import os
from pathlib import Path
import re
import tarfile
import tempfile
import unittest


class InstallerTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'Unix directory modes')
    def test_fresh_directories_survive_restrictive_installer_umask(self):
        from install_runtime import prepare_directory
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_mask = os.umask(0o077)
            try:
                for name, mode in [('program', 0o755), ('config', 0o750), ('router', 0o700)]:
                    path = root / name
                    prepare_directory(path, mode)
                    self.assertEqual(path.stat().st_mode & 0o777, mode)
                    path.chmod(0o700)
                    prepare_directory(path, mode)
                    self.assertEqual(path.stat().st_mode & 0o777, mode)
            finally:
                os.umask(old_mask)

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
