#!/bin/sh
set -eu
umask 077
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
[ "$(uname -s)" = Linux ] || die 'Linux required.'
[ "$(id -u)" = 0 ] || die 'Run this installer with sudo or as root.'
if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
    die 'An interactive terminal is required for the API key.'
fi
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    init=systemd
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    init=openrc
else
    die 'Supported service managers: systemd and OpenRC. No changes made.'
fi
if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 ca-certificates iputils-ping
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 ca-certificates iputils
elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 ca-certificates iputils
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 ca-certificates iputils
elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install python3 ca-certificates iputils
elif command -v pacman >/dev/null 2>&1; then
    pacman -S --needed --noconfirm python ca-certificates iputils
else
    say 'Unknown package manager: checking preinstalled dependencies.'
fi
command -v python3 >/dev/null 2>&1 || die 'Install Python 3.10 or newer.'
command -v ping >/dev/null 2>&1 || die 'Install iputils ping.'
python3 -c 'import sys,ssl; assert sys.version_info >= (3,10), "Python 3.10+ required"; assert ssl.create_default_context().get_ca_certs(), "CA certificates missing"'
stage=$(mktemp -d /tmp/roskompozor-install.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
chmod 755 "$stage"
say 'Checking ICMP support...'
ping -n -c 1 -W 2 127.0.0.1 >/dev/null 2>&1 || die 'ICMP unavailable: check container permissions / CAP_NET_RAW.'
cat > "$stage/roskompozor_probe.py" <<'PROBE_SOURCE'
#!/usr/bin/env python3
"""Standard-library probe for roskompozor.ru decentralized diagnostics."""
from __future__ import annotations
import concurrent.futures
import ipaddress
import json
import logging
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

LOG = logging.getLogger("roskompozor-probe")
USER_AGENT = "RoskompozorProbe/1.0"
MAX_REDIRECTS = 5
MAX_HEADER_BYTES = 65536

def error_type(exc: BaseException) -> str:
    if isinstance(exc, (TimeoutError, socket.timeout)): return "timeout"
    if isinstance(exc, socket.gaierror): return "DNS error"
    if isinstance(exc, ConnectionRefusedError): return "connection refused"
    if isinstance(exc, ConnectionResetError): return "connection reset"
    if isinstance(exc, ssl.SSLError): return "TLS error"
    return "HTTP error" if isinstance(exc, ValueError) else "network error"

def safe_error(exc: BaseException) -> str:
    return f"{error_type(exc)}: {str(exc)[:240]}"

def public_ip(value: str) -> bool:
    try: address = ipaddress.ip_address(value)
    except ValueError: return False
    return address.is_global and not any((address.is_loopback,address.is_private,address.is_link_local,address.is_multicast,address.is_reserved,address.is_unspecified))

def normalize_host(raw: str) -> str:
    raw=raw.strip().rstrip(".")
    if not raw or len(raw)>253 or any(ord(ch)<=32 for ch in raw): raise ValueError("invalid target")
    try: return str(ipaddress.ip_address(raw))
    except ValueError:
        host=raw.encode("idna").decode("ascii").lower()
        if not all(part and len(part)<=63 and part[0]!="-" and part[-1]!="-" and all(ch.isalnum() or ch=="-" for ch in part) for part in host.split(".")): raise ValueError("invalid target")
        return host

def resolve_public(host: str) -> list[str]:
    try: addresses=[str(ipaddress.ip_address(host))]
    except ValueError: addresses=sorted({item[4][0] for item in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)})
    if not addresses: raise socket.gaierror("DNS returned no addresses")
    if any(not public_ip(ip) for ip in addresses): raise ValueError("target resolved to a non-public address")
    return addresses[:4]

def tcp_check(ip: str,port: int,timeout: float) -> dict[str,Any]:
    started=time.monotonic()
    try:
        with socket.create_connection((ip,port),timeout=timeout): return {"ok":True,"ms":round((time.monotonic()-started)*1000),"ip":ip}
    except Exception as exc: return {"ok":False,"ms":round((time.monotonic()-started)*1000),"ip":ip,"error_type":error_type(exc),"error":safe_error(exc)}

def best_tcp(addresses: list[str],port: int,timeout: float) -> dict[str,Any]:
    attempts=[];good=None
    for ip in addresses:
        item=tcp_check(ip,port,timeout);attempts.append(item)
        if item["ok"]: good=item;break
    return {"ok":bool(good),"ms":(good or attempts[-1])["ms"],"attempts":attempts,**({"error":attempts[-1].get("error"),"error_type":attempts[-1].get("error_type")} if not good else {})}

def ping_check(ip: str,timeout: float) -> dict[str,Any]:
    started=time.monotonic();binary=shutil.which("ping")
    if not binary: return {"ok":False,"ms":0,"ip":ip,"error_type":"unavailable","error":"ping utility is unavailable"}
    command=[binary,"-n","-c","1","-W",str(max(1,int(timeout+0.999))),ip]
    if ":" in ip: command.insert(1,"-6")
    try:
        completed=subprocess.run(command,capture_output=True,text=True,timeout=timeout+2,check=False)
        output=(completed.stdout+" "+completed.stderr)[:4096];match=re.search(r"time[=<]([0-9.]+)\s*ms",output,re.I);elapsed=round((time.monotonic()-started)*1000)
        return {"ok":completed.returncode==0,"ms":round(float(match.group(1))) if match else elapsed,"ip":ip,**({"error_type":"no reply","error":"No ICMP reply; ping may be disabled"} if completed.returncode else {})}
    except Exception as exc: return {"ok":False,"ms":round((time.monotonic()-started)*1000),"ip":ip,"error_type":error_type(exc),"error":safe_error(exc)}

def best_ping(addresses: list[str],timeout: float) -> dict[str,Any]:
    attempts=[ping_check(ip,timeout) for ip in addresses];good=next((item for item in attempts if item["ok"]),None)
    return {"ok":bool(good),"ms":(good or attempts[-1])["ms"],"attempts":attempts,**({"error":attempts[-1].get("error"),"error_type":attempts[-1].get("error_type")} if not good else {})}

def tls_check(host: str,addresses: list[str],timeout: float) -> dict[str,Any]:
    attempts=[];context=ssl.create_default_context()
    for ip in addresses:
        started=time.monotonic()
        try:
            with socket.create_connection((ip,443),timeout=timeout) as plain:
                with context.wrap_socket(plain,server_hostname=host) as secure: cert=secure.getpeercert()
            subject=dict(part[0] for part in cert.get("subject",())).get("commonName");item={"ok":True,"ms":round((time.monotonic()-started)*1000),"ip":ip,"subject":subject,"expires":cert.get("notAfter")};attempts.append(item);return {**item,"attempts":attempts}
        except Exception as exc: attempts.append({"ok":False,"ms":round((time.monotonic()-started)*1000),"ip":ip,"error_type":error_type(exc),"error":safe_error(exc)})
    return {**attempts[-1],"attempts":attempts}

def parse_url(url: str) -> tuple[str,str,int,str]:
    parts=urllib.parse.urlsplit(url)
    if parts.scheme not in ("http","https") or not parts.hostname or parts.username or parts.password: raise ValueError("unsafe URL")
    port=parts.port or (443 if parts.scheme=="https" else 80)
    if port not in (80,443): raise ValueError("unsafe port")
    host=normalize_host(parts.hostname);path=urllib.parse.urlunsplit(("","",parts.path or "/",parts.query,""));return parts.scheme,host,port,path

def http_once(url: str,timeout: float) -> dict[str,Any]:
    scheme,host,port,path=parse_url(url);addresses=resolve_public(host);last=None
    for ip in addresses:
        started=time.monotonic()
        try:
            connection=socket.create_connection((ip,port),timeout=timeout)
            if scheme=="https": connection=ssl.create_default_context().wrap_socket(connection,server_hostname=host)
            host_header=f"[{host}]" if ":" in host else host
            request=f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n";connection.sendall(request.encode("ascii"));data=b""
            while b"\r\n\r\n" not in data and len(data)<MAX_HEADER_BYTES:
                chunk=connection.recv(4096)
                if not chunk: break
                data+=chunk
            connection.close();header=data.split(b"\r\n\r\n",1)[0].decode("iso-8859-1");lines=header.split("\r\n")
            if not lines or len(lines[0].split())<2: raise ValueError("invalid HTTP response")
            status=int(lines[0].split()[1]);headers={key.strip().lower():value.strip() for key,value in (line.split(":",1) for line in lines[1:] if ":" in line)}
            return {"ok":True,"status":status,"ms":round((time.monotonic()-started)*1000),"ip":ip,"location":headers.get("location")}
        except Exception as exc: last={"ok":False,"status":0,"ms":round((time.monotonic()-started)*1000),"ip":ip,"error_type":error_type(exc),"error":safe_error(exc)}
    return last or {"ok":False,"status":0,"ms":0,"error_type":"network error","error":"No public address"}

def http_chain(initial: str,timeout: float) -> dict[str,Any]:
    url=initial;chain=[]
    for redirect_count in range(MAX_REDIRECTS+1):
        result=http_once(url,timeout);result["url"]=url;chain.append(result);location=result.get("location")
        if not location or result.get("status") not in (301,302,303,307,308): break
        if redirect_count>=MAX_REDIRECTS: break
        url=urllib.parse.urljoin(url,location);parse_url(url)
    last=chain[-1]
    return {"ok":bool(last.get("ok")),"status":last.get("status",0),"ms":sum(int(item.get("ms",0)) for item in chain),"final_url":url,"chain":chain,**({"error":last.get("error"),"error_type":last.get("error_type")} if not last.get("ok") else {})}

def run_check(item: dict[str,Any],timeout: float) -> dict[str,Any]:
    started=time.monotonic()
    try:
        host=normalize_host(str(item.get("target","")));expected="ip" if public_ip(host) else "domain"
        if item.get("type")!=expected: raise ValueError("target type mismatch")
        raw_ports=item.get("ports",[]);ports=[]
        if not isinstance(raw_ports,list) or len(raw_ports)>8: raise ValueError("invalid ports")
        for raw_port in raw_ports:
            if isinstance(raw_port,bool) or not isinstance(raw_port,int) or raw_port<1 or raw_port>65535: raise ValueError("invalid port")
            if raw_port not in ports: ports.append(raw_port)
        ports=list(dict.fromkeys([80,443,*ports]));dns_started=time.monotonic();addresses=resolve_public(host);dns={"ok":True,"a":[ip for ip in addresses if ":" not in ip],"aaaa":[ip for ip in addresses if ":" in ip],"ms":round((time.monotonic()-dns_started)*1000)}
        check_timeout=min(timeout,3.0);ping=best_ping(addresses,min(check_timeout,2.0));tcp={}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports),10)) as port_executor:
            port_futures={port_executor.submit(best_tcp,addresses,port,min(check_timeout,2.0)):port for port in ports}
            for future,port in port_futures.items(): tcp[str(port)]=future.result()
        tls=tls_check(host,addresses,check_timeout) if tcp["443"]["ok"] else {"ok":False,"ms":0,"error_type":"connection refused","error":"TCP 443 is closed or filtered","attempts":[]}
        literal=f"[{host}]" if ":" in host else host
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as web_executor:
            http_future=web_executor.submit(http_chain,f"http://{literal}/",check_timeout);https_future=web_executor.submit(http_chain,f"https://{literal}/",check_timeout)
            http=http_future.result();https=https_future.result()
        ok=bool(tcp["80"]["ok"] or tcp["443"]["ok"] or http["ok"] or https["ok"])
        return {"ok":ok or ping["ok"],"target_type":expected,"summary":"Узел получил сетевой ответ" if ok or ping["ok"] else "Ответ на проверенные запросы не получен","dns":dns,"ping":ping,"tcp":tcp,"tls":tls,"http":http,"https":https,"total_ms":round((time.monotonic()-started)*1000)}
    except Exception as exc: return {"ok":False,"summary":"Проверка завершилась технической ошибкой","error_type":error_type(exc),"error":safe_error(exc),"total_ms":round((time.monotonic()-started)*1000)}

class ApiClient:
    def __init__(self,server: str,api_key: str,timeout: float):
        parts=urllib.parse.urlsplit(server)
        if parts.scheme not in ("http","https") or not parts.hostname or parts.username or parts.password: raise ValueError("invalid server URL")
        self.server=server.rstrip("/");self.api_key=api_key;self.timeout=timeout
    def request(self,path: str,payload: dict[str,Any]|None=None) -> dict[str,Any]:
        body=None if payload is None else json.dumps(payload,ensure_ascii=False,separators=(",",":")).encode();headers={"Authorization":f"Bearer {self.api_key}","Accept":"application/json","User-Agent":USER_AGENT}
        if body is not None: headers["Content-Type"]="application/json"
        request=urllib.request.Request(self.server+path,data=body,method="GET" if body is None else "POST",headers=headers)
        with urllib.request.urlopen(request,timeout=self.timeout) as response:
            if response.status!=200: raise RuntimeError(f"API HTTP {response.status}")
            data=json.loads(response.read(1048577))
        if not isinstance(data,dict): raise ValueError("invalid API response")
        return data

def load_config(path: Path) -> dict[str,Any]:
    config=json.loads(path.read_text(encoding="utf-8"));required=("server","api_key","poll_interval","request_timeout","max_parallel_checks")
    if not isinstance(config,dict) or any(key not in config for key in required): raise ValueError("incomplete configuration")
    if not isinstance(config["api_key"],str) or len(config["api_key"])<20: raise ValueError("invalid api_key")
    config["poll_interval"]=max(5,min(3600,int(config["poll_interval"])));config["request_timeout"]=max(2,min(60,float(config["request_timeout"])));config["max_parallel_checks"]=max(1,min(20,int(config["max_parallel_checks"])));return config

def main() -> int:
    logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s");path=Path(sys.argv[1] if len(sys.argv)>1 else Path(__file__).with_name("config.json"))
    try: config=load_config(path);client=ApiClient(config["server"],config["api_key"],config["request_timeout"])
    except Exception as exc: LOG.error("Configuration error: %s",safe_error(exc));return 2
    LOG.info("Probe started for %s",config["server"])
    while True:
        try:
            checks=client.request("/api/probe/checks").get("checks",[])
            if not isinstance(checks,list): raise ValueError("invalid checks response")
            if not checks: time.sleep(config["poll_interval"]);continue
            LOG.info("Received %d checks",len(checks));results=[]
            with concurrent.futures.ThreadPoolExecutor(max_workers=config["max_parallel_checks"]) as executor:
                futures={executor.submit(run_check,item,config["request_timeout"]):item for item in checks if isinstance(item,dict) and "id" in item}
                for future,item in futures.items():
                    try: result=future.result()
                    except Exception as exc: result={"ok":False,"summary":"Внутренняя ошибка узла","error_type":error_type(exc),"error":safe_error(exc)}
                    results.append({"check_id":str(item["id"]),"result":result})
            if results:
                reply=client.request("/api/probe/results",{"results":results});LOG.info("Submitted: accepted=%s duplicates=%s rejected=%s",reply.get("accepted",0),reply.get("duplicates",0),reply.get("rejected",0))
        except (urllib.error.URLError,urllib.error.HTTPError,TimeoutError,OSError,ValueError,RuntimeError,json.JSONDecodeError) as exc: LOG.warning("Temporary API error: %s",safe_error(exc));time.sleep(config["poll_interval"])
        except KeyboardInterrupt: LOG.info("Probe stopped");return 0

if __name__=="__main__": raise SystemExit(main())

PROBE_SOURCE
chmod 644 "$stage/roskompozor_probe.py"
python3 - "$stage" <<'PY'
import getpass, importlib.util, json, pathlib, re, sys, urllib.error, urllib.request
root = pathlib.Path(sys.argv[1])
source = root / 'roskompozor_probe.py'
compile(source.read_bytes(), str(source), 'exec')
spec = importlib.util.spec_from_file_location('probe', source)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
with open('/dev/tty', 'w') as tty:
    key = getpass.getpass('API key (input hidden): ', stream=tty).strip()
    if not re.fullmatch(r'rkp_[0-9a-fA-F]{64}', key):
        sys.exit('Invalid API key format. Expected rkp_ and 64 hexadecimal characters.')
    config = dict(server='https://roskompozor.ru', api_key=key, poll_interval=10,
                  request_timeout=10, max_parallel_checks=3)
    request = urllib.request.Request(config['server'] + '/api/probe/results',
        data=b'{"results":[]}', method='POST', headers={
        'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json',
        'User-Agent': probe.USER_AGENT})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
            data = json.load(response)
        if not isinstance(data, dict) or not all(k in data for k in ('accepted','duplicates','rejected')):
            raise ValueError('Unexpected API response')
    except urllib.error.HTTPError as exc:
        sys.exit('API validation failed: HTTP %s. Check key and whether the node is enabled.' % exc.code)
    except Exception as exc:
        sys.exit('API validation failed (%s). Check DNS, HTTPS, certificates and system clock.' % type(exc).__name__)
    (root / 'config.json').write_text(json.dumps(config, indent=2) + '\n')
    probe.load_config(root / 'config.json')
print('API key and HTTPS connection verified; no jobs claimed.')
PY
app=/opt/roskompozor-probe
conf=/etc/roskompozor-probe
name=roskompozor-probe
python=$(command -v python3)
if ! id "$name" >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /bin/false "$name"
    else
        addgroup -S "$name"
        adduser -S -D -H -h /nonexistent -s /bin/false -G "$name" "$name"
    fi
fi
group=$(id -gn "$name")
cat > "$stage/roskompozor-probe.service" <<EOF
[Unit]
Description=Roskompozor Probe
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=$name
Group=$group
WorkingDirectory=$app
ExecStart=$python $app/roskompozor_probe.py $conf/config.json
Restart=always
RestartSec=10
Environment=PYTHONDONTWRITEBYTECODE=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
cat > "$stage/openrc" <<EOF
#!/sbin/openrc-run
name="Roskompozor Probe"
command="$python"
command_args="$app/roskompozor_probe.py $conf/config.json"
command_user="$name:$group"
supervisor="supervise-daemon"
respawn_delay=10
respawn_max=0
retry="TERM/10/KILL/5"
output_log="/var/log/roskompozor-probe.log"
error_log="/var/log/roskompozor-probe.log"
capabilities="^cap_net_raw"
depend() { need net; }
EOF
if [ "$init" = systemd ]; then
    systemd-analyze verify "$stage/roskompozor-probe.service"
    systemd-run --quiet --wait --pipe --collect -p "User=$name" -p NoNewPrivileges=yes -p AmbientCapabilities=CAP_NET_RAW -p CapabilityBoundingSet=CAP_NET_RAW ping -n -c 1 -W 2 127.0.0.1 >/dev/null || die 'Service user cannot use ping.'
else
    command -v supervise-daemon >/dev/null 2>&1 || die 'OpenRC supervise-daemon required.'
    if ! supervise-daemon --help 2>&1 | grep -q -- '--capabilities'; then
        # Some distributions build OpenRC without libcap support. Their iputils
        # can instead use unprivileged ICMP sockets or its packaged file capability.
        su -s /bin/sh "$name" -c 'ping -n -c 1 -W 2 127.0.0.1' >/dev/null 2>&1 || die 'OpenRC has no capabilities support and unprivileged ping failed. Enable ICMP ping sockets for the service group.'
        sed '/^capabilities=/d' "$stage/openrc" > "$stage/openrc.tmp"
        mv "$stage/openrc.tmp" "$stage/openrc"
    fi
fi
backup=/var/backups/roskompozor-probe/$(date +%Y%m%d-%H%M%S)-$$
mkdir -p "$backup"
chmod 700 "$backup"
for path in "$app/roskompozor_probe.py" "$conf/config.json" /etc/systemd/system/roskompozor-probe.service /etc/init.d/roskompozor-probe; do
    if [ -e "$path" ]; then
        mkdir -p "$backup$(dirname "$path")"
        cp -p "$path" "$backup$path"
    fi
done
mkdir -p "$app" "$conf"
chmod 755 "$app"
chown root:"$group" "$conf"
chmod 750 "$conf"
install -m 644 "$stage/roskompozor_probe.py" "$app/roskompozor_probe.py"
install -m 640 "$stage/config.json" "$conf/config.json"
chown root:"$group" "$conf/config.json"
if [ "$init" = systemd ]; then
    install -m 644 "$stage/roskompozor-probe.service" /etc/systemd/system/roskompozor-probe.service
    systemctl daemon-reload
    systemctl enable "$name"
    systemctl restart "$name"
    sleep 3
    systemctl is-active --quiet "$name" || die "Service failed. Backup: $backup; inspect journalctl -u $name"
else
    if [ ! -e /var/log/roskompozor-probe.log ]; then
        touch /var/log/roskompozor-probe.log
    fi
    chown "$name:$group" /var/log/roskompozor-probe.log
    chmod 640 /var/log/roskompozor-probe.log
    install -m 755 "$stage/openrc" /etc/init.d/roskompozor-probe
    rc-update add "$name" default
    rc-service "$name" restart
    sleep 3
    rc-service "$name" status || die "Service failed. Backup: $backup"
fi
python3 - "$app/roskompozor_probe.py" <<'PY'
import pathlib, sys
target = sys.argv[1].encode()
for process in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
    try:
        if target in process.read_bytes().split(b'\0')[1:2]:
            break
    except OSError:
        continue
else:
    sys.exit('Probe process not running. Inspect the service log and backup before retrying.')
PY
say "Probe installed and running. Backup: $backup"
