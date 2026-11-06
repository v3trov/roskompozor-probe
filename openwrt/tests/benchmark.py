"""Resource comparison on identical local fixtures; not router measurements."""
import json
from pathlib import Path
import subprocess
from test_native import NativeTests, ROOT, NATIVE

NativeTests.setUpClass()
try:
    path = NativeTests.directory / 'benchmark.json'
    item = dict(target='example.com', type='domain', ports=[1380, 9999])
    path.write_text(json.dumps(item))
    commands = {
        'native': [str(NATIVE), '--check', str(path)],
        'python': ['python3', '-c', f'import sys;sys.path.insert(0,{str(ROOT)!r});import roskompozor_probe as p;import json;print(json.dumps(p.run_check({item!r},10)))'],
    }
    sanitizer = Path('/root/rkp-openwrt-build/probe-ubsan')
    if sanitizer.exists():
        subprocess.run([str(sanitizer), '--check', str(path)], env=NativeTests.env, capture_output=True, check=True, timeout=30)
    for label, command in commands.items():
        results = []
        for _ in range(5):
            process = subprocess.run(['/usr/bin/time', '-f', '%M %U %S', *command], env=NativeTests.env, capture_output=True, text=True, check=True, timeout=30)
            rss, user, system = process.stderr.strip().splitlines()[-1].split()
            results.append(dict(max_rss_kib=int(rss), user_seconds=float(user), system_seconds=float(system)))
        print(json.dumps(dict(client=label, samples=results)))
finally:
    NativeTests.tearDownClass()
