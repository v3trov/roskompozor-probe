"""Rebuild the self-contained installer deterministically; no network or secrets."""
import base64
import gzip
import hashlib
import io
from pathlib import Path
import tarfile

ROOT=Path(__file__).resolve().parent
FILES=['roskompozor_probe.py','next/network.py','next/probe_next.py','next/install_runtime.py',
       'next/roskompozor-probe-next.service','next/openwrt.init','next/openrc.init','next/direct-route.nft',
       'next/luci-helper','next/luci-view.js','next/luci-acl.json','next/luci-menu.json']

def build():
    stream=io.BytesIO()
    with gzip.GzipFile(fileobj=stream,mode='wb',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w') as archive:
            for name in sorted(FILES):
                data=(ROOT/name).read_bytes().replace(b'\r\n',b'\n')
                entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=0o644;entry.mtime=0
                archive.addfile(entry,io.BytesIO(data))
    bundle=stream.getvalue()
    template=(ROOT/'install.template.sh').read_text(encoding='utf-8')
    script=template.replace('__BUNDLE_BASE64__',base64.b64encode(bundle).decode()).replace('__BUNDLE_SHA256__',hashlib.sha256(bundle).hexdigest())
    (ROOT/'install.sh').write_text(script,encoding='utf-8',newline='\n')
    print('Installer rebuilt:',len(script),'bytes')

if __name__=='__main__':build()
