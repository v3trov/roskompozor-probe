#!/bin/sh
set -eu
umask 077
[ "$(id -u)" = 0 ] || { echo 'Run as root.' >&2; exit 1; }
dependencies_ready=0
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys,ssl,sqlite3,concurrent.futures,urllib.request,ipaddress; assert sys.version_info >= (3,9); assert ssl.create_default_context().get_ca_certs()' >/dev/null 2>&1; then
    dependencies_ready=1
fi
if [ "$dependencies_ready" = 1 ]; then
    :
elif [ -r /etc/openwrt_release ]; then
    available=$(df -Pk /overlay | awk 'NR==2 {print $4}')
    [ "$available" -ge 18000 ] || { echo 'At least 18 MiB of free overlay space required.' >&2; exit 1; }
    opkg update
    opkg install python3 ca-bundle
elif command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 ca-certificates iputils-ping
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 ca-certificates iputils shadow
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 ca-certificates iputils
elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 ca-certificates iputils
elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install python3 ca-certificates iputils
elif command -v pacman >/dev/null 2>&1; then
    pacman -S --needed --noconfirm python ca-certificates iputils
fi
command -v python3 >/dev/null 2>&1 || { echo 'Python 3.9+ required.' >&2; exit 1; }
stage=$(mktemp -d /tmp/roskompozor-install.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
export PROBE_INSTALL_STAGE="$stage"
python3 - <<'BUNDLE'
import base64,hashlib,io,os,pathlib,ssl,sys,tarfile
assert sys.version_info >= (3,9),'Python 3.9+ required'
assert ssl.create_default_context().get_ca_certs(),'CA certificates required'
data=base64.b64decode('__BUNDLE_BASE64__')
assert hashlib.sha256(data).hexdigest()=='__BUNDLE_SHA256__'
root=pathlib.Path(os.environ['PROBE_INSTALL_STAGE'])
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
 for member in archive:
  path=pathlib.PurePosixPath(member.name)
  assert member.isfile() and not path.is_absolute() and '..' not in path.parts
  target=root.joinpath(*path.parts);target.parent.mkdir(parents=True,exist_ok=True)
  target.write_bytes(archive.extractfile(member).read())
BUNDLE
python3 "$stage/next/install_runtime.py"
echo 'Probe 2.0.1 installed: roskompozor-probe-next'
