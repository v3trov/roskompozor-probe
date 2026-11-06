"""Run differential tests with the actual ARM64/musl/OpenWrt libraries via QEMU.
Usage: python3 openwrt/tests/test_openwrt_runtime.py /path/to/sdk
Requires qemu-aarch64 and the SDK dependencies already built.
"""
import os
import io
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import tarfile
import unittest
import test_native

sdk = Path(sys.argv[1]).resolve()
target = next((sdk / 'staging_dir').glob('target-aarch64*'))
toolchain = next((sdk / 'staging_dir').glob('toolchain-aarch64*'))
cc = toolchain / 'bin/aarch64-openwrt-linux-musl-gcc'
loader = toolchain / 'lib/ld-musl-aarch64.so.1'
source = Path(__file__).resolve().parent
env = dict(os.environ, STAGING_DIR=str(target))
common = ['-I' + str(target / 'usr/include'), '-L' + str(target / 'usr/lib'), '-Wl,-rpath-link,' + str(target / 'usr/lib')]
libs = ['-lssl', '-lcrypto', '-ljson-c', '-lcurl', '-lidn', '-lpthread', '-lm']

with tempfile.TemporaryDirectory(prefix='rkp-arm-runtime-') as directory:
    directory = Path(directory)
    binary = directory / 'probe-arm'
    harness = directory / 'harness-arm'
    shim = directory / 'netshim-arm.so'
    package = sorted((sdk / 'bin/packages').glob('aarch64_cortex-a53/base/roskompozor-probe_*.ipk'))[-1]
    with tarfile.open(package) as archive:
        with tarfile.open(fileobj=io.BytesIO(archive.extractfile('./data.tar.gz').read())) as data:
            binary.write_bytes(data.extractfile('./usr/bin/roskompozor-probe').read())
            binary.chmod(0o755)
    print('Testing packaged ARM64 binary:', package.name, binary.stat().st_size, 'bytes', flush=True)
    for filename, output, extra in [
        (source / 'harness.c', harness, libs),
        (source / 'netshim.c', shim, ['-shared', '-fPIC', '-ldl'])
    ]:
        subprocess.run([str(cc), '-std=c11', '-Os', *common, str(filename), *extra, '-o', str(output)], env=env, check=True)
    library_path = str(target / 'usr/lib') + ':' + str(toolchain / 'lib')
    wrappers = []
    for executable in (binary, harness):
        wrapper = directory / (executable.name + '.sh')
        args = ['/usr/bin/env', '-u', 'LD_PRELOAD', '/usr/bin/qemu-aarch64', '-E', 'LD_PRELOAD=' + str(shim), str(loader), '--library-path', library_path, str(executable)]
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.join(args) + ' "$@"\n')
        wrapper.chmod(0o755)
        wrappers.append(wrapper)
    test_native.NATIVE, test_native.HARNESS = wrappers
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_native.NativeTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        sys.exit(1)
