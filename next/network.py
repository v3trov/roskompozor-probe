"""Bounded experimental measurements. Every target socket uses the public-IP gate."""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import time

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import roskompozor_probe as legacy

VERSION = '2.0.0'
RESOLVERS = (
    ('cloudflare', '1.1.1.1', 'cloudflare-dns.com', '/dns-query'),
    ('google', '8.8.8.8', 'dns.google', '/dns-query'),
)


class IncompletePayload(Exception):
    def __init__(self, received, expected, reason):
        self.received, self.expected, self.reason = received, expected, reason


def failure(error):
    # Socket messages and URLs need not be retained to diagnose the stage.
    return {'ok': False, 'error_type': legacy.error_type(error)}


def left(deadline, cap=3.0):
    return legacy.remaining_timeout(deadline, cap)


def connect_public(ip, port, deadline):
    if not legacy.public_ip(ip) or not 1 <= port <= 65535:
        raise ValueError('non-public destination')
    stream = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM)
    try:
        stream.settimeout(left(deadline))
        stream.connect((ip, port))
        return stream
    except BaseException:
        stream.close()
        raise


def receive_exact(stream, count, deadline):
    result = b''
    while len(result) < count:
        stream.settimeout(left(deadline))
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise ValueError('short response')
        result += chunk
    return result


def system_dns(host, timeout=4):
    """getaddrinfo in a killable process; its libc timeout cannot strand workers."""
    host = legacy.normalize_host(host)
    if os.environ.get('ROSKOMPOZOR_DIRECT_DNS') == '1':
        try:
            return {'ok': True, 'addresses': direct_addresses(host), 'source': 'configured_direct'}
        except Exception:
            return {'ok': False, 'error_type': 'DNS error', 'addresses': [], 'source': 'configured_direct'}
    code = ('import socket,json,sys; print(json.dumps(sorted({a[4][0] for a in '
            'socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)})))')
    try:
        reply = subprocess.run([sys.executable, '-c', code, host], capture_output=True,
                               timeout=timeout, check=True, text=True)
        addresses = json.loads(reply.stdout)
        if not addresses or len(addresses) > 128:
            raise ValueError('invalid resolver result')
        if any(not legacy.public_ip(ip) for ip in addresses):
            return {'ok': False, 'error_type': 'non_public_answer', 'addresses': []}
        return {'ok': True, 'addresses': addresses}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error_type': 'timeout', 'addresses': []}
    except Exception:
        return {'ok': False, 'error_type': 'DNS error', 'addresses': []}


def dns_name(data, position):
    labels, visited, end = [], set(), None
    while True:
        if position in visited or position >= len(data) or len(visited) > 128:
            raise ValueError('invalid DNS name')
        visited.add(position)
        length = data[position]
        if length & 0xc0 == 0xc0:
            if position + 1 >= len(data):
                raise ValueError('short DNS pointer')
            end = end or position + 2
            position = ((length & 63) << 8) | data[position + 1]
            continue
        if length > 63 or position + 1 + length > len(data):
            raise ValueError('invalid DNS label')
        position += 1
        if not length:
            return '.'.join(labels).lower(), end or position
        labels.append(data[position:position + length].decode('ascii'))
        position += length


def dns_packet(host, kind):
    host = legacy.normalize_host(host)
    ident = secrets.randbelow(65536)
    question = b''.join(bytes([len(label)]) + label.encode('ascii') for label in host.split('.'))
    return ident, struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + question + b'\0' + struct.pack('!2H', kind, 1)


def parse_dns(data, ident, host, kind):
    if len(data) < 12:
        raise ValueError('short DNS header')
    actual, flags, qd, an, ns, ar = struct.unpack('!6H', data[:12])
    if actual != ident or not flags & 0x8000 or flags & 0x7800 or qd != 1:
        raise ValueError('unexpected DNS reply')
    name, position = dns_name(data, 12)
    if name != host or data[position:position + 4] != struct.pack('!2H', kind, 1):
        raise ValueError('unexpected DNS question')
    position += 4
    addresses = []
    for _ in range(an):
        _, position = dns_name(data, position)
        if position + 10 > len(data):
            raise ValueError('short DNS record')
        record_type, record_class, ttl, length = struct.unpack('!HHIH', data[position:position + 10])
        position += 10
        if position + length > len(data):
            raise ValueError('short DNS value')
        if record_class == 1 and record_type == kind and length == (4 if kind == 1 else 16):
            addresses.append(str(ipaddress.ip_address(data[position:position + length])))
        position += length
    return {'ok': True, 'rcode': flags & 15, 'truncated': bool(flags & 0x200),
            'addresses': sorted(set(addresses))}


def read_http(stream, deadline, limit):
    """Read a bounded non-redirecting control response, retaining only counters."""
    data = b''
    while b'\r\n\r\n' not in data:
        stream.settimeout(left(deadline))
        chunk = stream.recv(4096)
        if not chunk:
            raise ValueError('incomplete HTTP header')
        data += chunk
        if len(data) > 65536:
            raise ValueError('oversized HTTP header')
    header, body = data.split(b'\r\n\r\n', 1)
    lines = header.split(b'\r\n')
    parts = lines[0].split()
    if len(parts) < 2 or not parts[0].startswith(b'HTTP/'):
        raise ValueError('invalid HTTP status')
    status = int(parts[1])
    headers = dict(line.lower().split(b':', 1) for line in lines[1:] if b':' in line)
    if b'transfer-encoding' in headers:
        raise ValueError('control must provide Content-Length')
    length = int(headers.get(b'content-length', b'0').strip())
    if length < 0 or length > limit:
        raise ValueError('unexpected control response length')
    body = body[:length]
    while len(body) < length:
        try:
            stream.settimeout(left(deadline))
            chunk = stream.recv(min(8192, length - len(body)))
        except (OSError, TimeoutError) as error:
            raise IncompletePayload(len(body), length, legacy.error_type(error)) from error
        if not chunk:
            break
        body += chunk
    return status, body, length


def dns_query(resolver, protocol, host, kind, timeout=3):
    name, ip, tls_name, path = resolver
    result = {'provider': name, 'protocol': protocol, 'record': 'A' if kind == 1 else 'AAAA'}
    ident, packet = dns_packet(host, kind)
    deadline, started = time.monotonic() + timeout, time.monotonic()
    stream = None
    try:
        if protocol == 'udp':
            if not legacy.public_ip(ip):
                raise ValueError('unsafe resolver')
            stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            stream.settimeout(left(deadline))
            stream.connect((ip, 53))  # Kernel rejects datagrams from other peers.
            stream.send(packet)
            data = stream.recv(65535)
        else:
            port = {'tcp': 53, 'dot': 853, 'doh': 443}[protocol]
            stream = connect_public(ip, port, deadline)
            if protocol in ('dot', 'doh'):
                stream.settimeout(left(deadline))
                stream = ssl.create_default_context().wrap_socket(stream, server_hostname=tls_name)
            if protocol == 'doh':
                request = (f'POST {path} HTTP/1.1\r\nHost: {tls_name}\r\n'
                           f'Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n'
                           f'Content-Length: {len(packet)}\r\nConnection: close\r\n\r\n').encode() + packet
                stream.settimeout(left(deadline)); stream.sendall(request)
                status, data, length = read_http(stream, deadline, 65535)
                if status != 200 or len(data) != length:
                    raise ValueError('invalid DoH response')
            else:
                stream.settimeout(left(deadline)); stream.sendall(struct.pack('!H', len(packet)) + packet)
                count = struct.unpack('!H', receive_exact(stream, 2, deadline))[0]
                data = receive_exact(stream, count, deadline)
        result.update(parse_dns(data, ident, host, kind))
    except Exception as error:
        result.update(failure(error))
    finally:
        if stream is not None:
            stream.close()
    result['ms'] = round((time.monotonic() - started) * 1000)
    return result


def compare_dns(host):
    jobs = [(resolver, protocol, host, kind) for resolver in RESOLVERS
            for protocol in ('udp', 'tcp', 'dot', 'doh') for kind in (1, 28)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        observations = list(executor.map(lambda args: dns_query(*args), jobs))
    differences, comparisons = [], 0
    for resolver in RESOLVERS:
        for record in ('A', 'AAAA'):
            rows = [r for r in observations if r['provider'] == resolver[0] and r['record'] == record
                    and r.get('ok') and not r.get('truncated')]
            reference = next((r for r in rows if r['protocol'] == 'doh'), None)
            if reference:
                for row in rows:
                    if row['protocol'] != 'doh' and (row['rcode'], row['addresses']) != (reference['rcode'], reference['addresses']):
                        differences.append({'provider': resolver[0], 'protocol': row['protocol'], 'record': record})
                    if row['protocol'] != 'doh':
                        comparisons += 1
    return {'observations': observations, 'differences': differences,
            'comparisons': comparisons,
            'interpretation': ('insufficient_data' if not comparisons else
                               'answers_differ' if differences else 'no_difference_observed'),
            'spoofing_proven': False}


def tls_attempt(host, ip, verify, timeout=3):
    started, stream = time.monotonic(), None
    stage = 'tcp'
    try:
        deadline = started + timeout
        stream = connect_public(ip, 443, deadline)
        stage = 'tls'
        context = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        stream.settimeout(left(deadline))
        stream = context.wrap_socket(stream, server_hostname=host)
        return {'ok': True, 'ip': ip, 'stage': 'tls', 'version': stream.version(),
                'certificate_verified': verify, 'ms': round((time.monotonic() - started) * 1000)}
    except Exception as error:
        return {**failure(error), 'ip': ip, 'stage': stage,
                'certificate_error': isinstance(error, ssl.SSLCertVerificationError),
                'ms': round((time.monotonic() - started) * 1000)}
    finally:
        if stream is not None:
            stream.close()


def family_measurements(host, addresses, dns_ok=True):
    # Both families are always represented. No global 'best IP' hides one family.
    groups = {'ipv4': [ip for ip in addresses if ':' not in ip][:2],
              'ipv6': [ip for ip in addresses if ':' in ip][:2]}
    results = {}
    for family, ips in groups.items():
        if not ips:
            results[family] = {'status': 'no_address' if dns_ok else 'dns_unavailable', 'attempts': []}
            continue
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            attempts = list(executor.map(lambda ip: {'ip': ip,
                'tcp80': legacy.tcp_check(ip, 80, 2), 'tcp443': legacy.tcp_check(ip, 443, 2),
                'tls_verified': tls_attempt(host, ip, True),
                'tls_handshake': tls_attempt(host, ip, False)}, ips))
        results[family] = {'status': 'measured', 'attempts': attempts}
    return results


def control_attempt(control, sni, timeout=4):
    """Only explicitly configured owned controls may transfer a bounded body."""
    ip = control['ip']
    sni = legacy.normalize_host(sni)
    port = int(control.get('port', 443))
    size = int(control.get('bytes', 65536))
    if port != 443 or not 1024 <= size <= 65536:
        raise ValueError('invalid control settings')
    started, stream, stage = time.monotonic(), None, 'tcp'
    try:
        deadline = started + timeout
        stream = connect_public(ip, port, deadline)
        stage = 'tls'
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Intentional only for controlled SNI/handshake experiments.
        stream.settimeout(left(deadline)); stream = context.wrap_socket(stream, server_hostname=sni)
        stage = 'data'
        request_host = legacy.normalize_host(control.get('sni', 'probe-control.invalid'))
        request = (f'GET /probe-control/{size} HTTP/1.1\r\nHost: {request_host}\r\n'
                   'Accept-Encoding: identity\r\nConnection: close\r\n\r\n').encode('ascii')
        stream.settimeout(left(deadline)); stream.sendall(request)
        status, body, expected = read_http(stream, deadline, size)
        # Count only; do not return or persist the received payload.
        return {'ok': status == 200 and expected == size and len(body) == size,
                'stage': stage, 'status': status, 'received_bytes': len(body),
                'expected_bytes': size, 'ms': round((time.monotonic() - started) * 1000)}
    except Exception as error:
        extra = ({'received_bytes': error.received, 'expected_bytes': error.expected,
                  'error_type': error.reason} if isinstance(error, IncompletePayload) else {})
        return {**failure(error), **extra, 'stage': stage, 'ms': round((time.monotonic() - started) * 1000)}
    finally:
        if stream is not None:
            stream.close()


def sni_controls(host, controls):
    results = []
    for control in controls[:2]:
        if control.get('scope') and host not in control['scope']:
            results.append({'id': control['id'], 'interpretation': 'outside_control_scope',
                            'blocking_proven': False})
            continue
        # Before/after baseline reduces transient failures being attributed to SNI.
        baseline_sni = legacy.normalize_host(control.get('sni', 'probe-control.invalid'))
        before = control_attempt(control, baseline_sni)
        if not before['ok']:
            results.append({'id': control['id'], 'baseline_before': before,
                            'interpretation': 'control_unavailable', 'blocking_proven': False})
            continue
        candidate = control_attempt(control, host)
        after = control_attempt(control, baseline_sni)
        state = 'control_unavailable'
        if before['ok'] and after['ok']:
            state = 'no_difference_observed' if candidate['ok'] else 'target_sni_difference'
        results.append({'id': control['id'], 'baseline_before': before, 'candidate': candidate,
                        'baseline_after': after, 'interpretation': state, 'blocking_proven': False})
    return results


def legacy_measurement(item):
    code = ('import json,sys; sys.path.insert(0,' + repr(str(Path(__file__).parent)) + '); '
            'import network; import roskompozor_probe as p; '
            'print(json.dumps(p.run_check(json.load(sys.stdin),3),ensure_ascii=True))')
    try:
        result = subprocess.run([sys.executable, '-c', code], input=json.dumps(item), text=True,
                                capture_output=True, timeout=32, cwd=str(Path(legacy.__file__).parent), check=True)
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error_type': 'timeout', 'summary': 'Measurement deadline exceeded'}
    except Exception:
        return {'ok': False, 'error_type': 'network error', 'summary': 'Measurement failed'}


def measure(item, controls):
    started = time.monotonic()
    host = legacy.normalize_host(item['target'])
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if item.get('type') != ('ip' if is_ip else 'domain'):
        raise ValueError('target type mismatch')
    if is_ip and not legacy.public_ip(host):
        raise ValueError('non-public target')
    ports = item.get('ports', [])
    if not isinstance(ports, list) or len(ports) > 8 or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError('invalid ports')
    for control in controls:
        if not legacy.public_ip(control['ip']):
            raise ValueError('non-public control')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        normal = executor.submit(legacy_measurement, item)
        dns_future = None if is_ip else executor.submit(compare_dns, host)
        sni_future = None if is_ip else executor.submit(sni_controls, host, controls)
        system = system_dns(host)
        # Never connect to independent DNS answers. Real-site traffic uses only
        # validated system answers; all answers are checked before selecting any.
        family = executor.submit(family_measurements, host, system.get('addresses', []), system['ok'])
        result = normal.result()
        result['experimental'] = {'version': VERSION, 'system_dns': system,
            'dns_comparison': dns_future.result() if dns_future else {'status': 'not_applicable'},
            'sni_controls': sni_future.result() if sni_future else [], 'families': family.result()}
    result['total_ms'] = round((time.monotonic() - started) * 1000)
    return result


_original_getaddrinfo = socket.getaddrinfo
_direct_cache = {}


def direct_addresses(host):
    """Explicit router mode: do not ask a local DNS proxy for target addresses."""
    host = legacy.normalize_host(host)
    try:
        ipaddress.ip_address(host)
        return [host] if legacy.public_ip(host) else []
    except ValueError:
        pass
    cached = _direct_cache.get(host)
    if cached and cached[0] > time.monotonic():
        return cached[1]
    for resolver in RESOLVERS:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            rows = list(executor.map(lambda kind: dns_query(resolver, 'udp', host, kind, 2), (1, 28)))
        addresses = sorted({ip for row in rows if row.get('ok') and not row.get('truncated')
                            and row.get('rcode') == 0 for ip in row['addresses']})
        if addresses:
            if any(not legacy.public_ip(ip) for ip in addresses):
                raise ValueError('non-public DNS answer')
            if len(_direct_cache) > 256:
                _direct_cache.clear()
            _direct_cache[host] = (time.monotonic() + 30, addresses)
            return addresses
    raise socket.gaierror('direct DNS returned no public addresses')


def direct_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host is None:
        return _original_getaddrinfo(host, port, family, type, proto, flags)
    if isinstance(host, bytes):
        host = host.decode('ascii')
    try:
        ipaddress.ip_address(host)
        return _original_getaddrinfo(host, port, family, type, proto, flags)
    except ValueError:
        pass
    port = int(port) if str(port).isdigit() else socket.getservbyname(port, 'tcp')
    addresses = direct_addresses(host)
    rows = []
    for ip in addresses:
        af = socket.AF_INET6 if ':' in ip else socket.AF_INET
        if family not in (0, socket.AF_UNSPEC, af):
            continue
        rows.append((af, type or socket.SOCK_STREAM, proto or socket.IPPROTO_TCP, '',
                     (ip, port, 0, 0) if af == socket.AF_INET6 else (ip, port)))
    if not rows:
        raise socket.gaierror('requested address family unavailable')
    return rows


if os.environ.get('ROSKOMPOZOR_DIRECT_DNS') == '1':
    socket.getaddrinfo = direct_getaddrinfo


_original_socket = socket.socket
if os.environ.get('ROSKOMPOZOR_SOCKET_MARK'):
    _mark = int(os.environ['ROSKOMPOZOR_SOCKET_MARK'], 0)
    if _mark != 0x48000000:
        raise ValueError('unsupported direct-route socket mark')

    class DirectSocket(_original_socket):
        def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
            super().__init__(family, type, proto, fileno)
            if self.family in (socket.AF_INET, socket.AF_INET6):
                try:
                    self.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_MARK', 36), _mark)
                except BaseException:
                    self.close()
                    raise  # Fail closed: never silently measure through the proxy.

    socket.socket = DirectSocket
