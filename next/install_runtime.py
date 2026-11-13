#!/usr/bin/env python3
"""Install an extracted, verified Probe bundle; no credentials in arguments."""
import datetime
import getpass
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def install(source, supplied=None):
    if os.geteuid():
        raise RuntimeError('Run as root')
    router = Path('/etc/openwrt_release').exists()
    systemd = Path('/run/systemd/system').is_dir()
    if not router and not systemd and not shutil.which('rc-service'):
        raise RuntimeError('systemd, OpenRC or OpenWrt required')
    app = Path('/opt/roskompozor-probe-next')
    conf = Path('/etc/roskompozor-probe-next')
    previous = json.loads((conf / 'config.json').read_text()) if (conf / 'config.json').exists() else {}
    config = dict(previous)
    if supplied:
        config.update(supplied)
    config['mode'] = 'api'
    config['server'] = 'https://roskompozor.ru'
    if not config.get('api_key'):
        config['api_key'] = getpass.getpass('Probe API key: ', stream=open('/dev/tty', 'w'))
    if not isinstance(config['api_key'], str) or not config['api_key'].startswith('rkp_') or len(config['api_key']) != 68:
        raise ValueError('Invalid Probe API key')
    config['parallel'] = min(2, max(1, int(config.get('parallel', 1))))
    config['interval'] = 300
    config['controls'] = config.get('controls', [
        {'id': 'owned-ru-web', 'ip': '37.194.95.150', 'sni': 'probe-control.roskompozor.ru', 'bytes': 65536},
        {'id': 'owned-eu', 'ip': '185.225.205.43', 'sni': 'probe-control.invalid', 'bytes': 65536}])
    # Scope of the old trial is deliberately removed in the production runtime.
    for control in config['controls']:
        control.pop('scope', None)
    config['state_dir'] = str(conf / 'state') if router else '/var/lib/roskompozor-probe-next/api'
    if router:
        config['direct_dns'] = True
        # Explicitly configured, owned local API endpoint only. Other targets
        # retain public-IP validation and use the normal WAN route.
        if 'api_connect_ip' not in config:
            old = Path('/etc/roskompozor-probe/config.json')
            if old.exists():
                config['api_connect_ip'] = json.loads(old.read_text()).get('api_connect_ip', '')
    account = None
    if not router:
        try:
            account = pwd.getpwnam('roskompozor-probe-next')
        except KeyError:
            run('useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', 'roskompozor-probe-next')
            account = pwd.getpwnam('roskompozor-probe-next')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    backup = Path('/etc/roskompozor-probe-next-backups' if router else '/var/backups/roskompozor-probe-next') / stamp
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(backup.parent, 0o700)
    unit = Path('/etc/init.d/roskompozor-probe-next' if router or not systemd else '/etc/systemd/system/roskompozor-probe-next.service')
    if (conf / 'config.json').exists():
        shutil.copy2(conf / 'config.json', backup / 'config.json')
    if unit.exists():
        shutil.copy2(unit, backup / 'service')
    if app.exists():
        # Queue/state are outside the program tree and are never copied/erased.
        shutil.copytree(app, backup / 'program', ignore=shutil.ignore_patterns('__pycache__'))
    app.mkdir(mode=0o755, parents=True, exist_ok=True)
    (app / 'next').mkdir(mode=0o755, exist_ok=True)
    conf.mkdir(mode=0o750, exist_ok=True)
    old_active = False
    try:
        if systemd:
            old_active = subprocess.call(['systemctl', 'is-active', '--quiet', 'roskompozor-probe-next']) == 0
            if old_active: run('systemctl', 'stop', 'roskompozor-probe-next')
        elif unit.exists():
            subprocess.run([str(unit), 'stop'], check=False, stdout=subprocess.DEVNULL)
        for name in ('roskompozor_probe.py', 'next/network.py', 'next/probe_next.py'):
            shutil.copyfile(source / name, app / name)
            os.chmod(app / name, 0o644)
        config_path = conf / 'config.json'
        temporary = conf / 'config.json.new'
        temporary.write_text(json.dumps(config, indent=2) + '\n')
        os.chmod(temporary, 0o640 if account else 0o600)
        if account:
            os.chown(conf, 0, account.pw_gid); os.chown(temporary, 0, account.pw_gid)
        temporary.replace(config_path)
        if router:
            for name in ('openwrt.init', 'direct-route.nft'):
                shutil.copyfile(source / 'next' / name, conf / name)
            if config.get('api_connect_ip'):
                import ipaddress
                local = ipaddress.ip_address(config['api_connect_ip'])
                if local.version != 4 or not local.is_private:
                    raise ValueError('Local API pin must be an explicitly owned LAN IPv4 address')
                rules = (source / 'next/direct-route.nft').read_text().replace('192.168.1.220', str(local))
            else:
                rules = 'chain probe_direct_counter { type filter hook output priority -149; policy accept; meta mark & 0x08000000 != 0 counter; }\n'
            firewall = Path('/etc/nftables.d/90-roskompozor-probe.nft')
            if firewall.exists(): shutil.copy2(firewall, backup / 'firewall.nft')
            firewall.write_text(rules)
            # Scoped update; never flush/restart the user's firewall or ZeroBlock.
            subprocess.run(['nft', 'flush', 'chain', 'inet', 'fw4', 'probe_direct_counter'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['nft', 'flush', 'chain', 'inet', 'fw4', 'probe_local_api'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['nft', 'delete', 'chain', 'inet', 'fw4', 'probe_direct_counter'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['nft', 'delete', 'chain', 'inet', 'fw4', 'probe_local_api'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['nft', '-f', '-'], input='table inet fw4 {\n' + rules + '\n}\n', text=True, check=True)
            shutil.copyfile(source / 'next/openwrt.init', unit); os.chmod(unit, 0o755)
            if Path('/www/luci-static/resources').is_dir():
                for name, destination, mode in [
                    ('luci-view.js', '/www/luci-static/resources/view/roskompozor-probe.js', 0o644),
                    ('luci-helper', '/usr/libexec/roskompozor-probe-config', 0o755),
                    ('luci-acl.json', '/usr/share/rpcd/acl.d/luci-app-roskompozor-probe.json', 0o644),
                    ('luci-menu.json', '/usr/share/luci/menu.d/luci-app-roskompozor-probe.json', 0o644),
                ]:
                    target = Path(destination)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists(): shutil.copy2(target, backup / name)
                    shutil.copyfile(source / 'next' / name, target); os.chmod(target, mode)
                for cache in Path('/tmp').glob('luci-indexcache*'):
                    if cache.is_file(): cache.unlink()
                subprocess.run(['/etc/init.d/rpcd', 'reload'], check=False, stdout=subprocess.DEVNULL)
            run(str(unit), 'enable'); run(str(unit), 'start')
        elif systemd:
            shutil.copyfile(source / 'next/roskompozor-probe-next.service', unit)
            run('systemctl', 'daemon-reload'); run('systemctl', 'enable', '--now', 'roskompozor-probe-next')
        else:
            shutil.copyfile(source / 'next/openrc.init', unit); os.chmod(unit, 0o755)
            run('rc-update', 'add', 'roskompozor-probe-next', 'default'); run('rc-service', 'roskompozor-probe-next', 'start')
        environment = os.environ.copy()
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        if router:
            environment.update(ROSKOMPOZOR_DIRECT_DNS='1', ROSKOMPOZOR_SOCKET_MARK='0x48000000')
        verify = ('import json; from probe_next import Api; '
                  'c=json.load(open("/etc/roskompozor-probe-next/config.json")); '
                  'r=Api(c).request("/api/probe/results",{"results":[]}); '
                  'assert r["accepted"]==r["duplicates"]==r["rejected"]==0')
        subprocess.run([sys.executable, '-c', verify], cwd=app / 'next', env=environment,
                       check=True, timeout=30, stdout=subprocess.DEVNULL)
        if not config.get('keep_legacy'):
            if systemd:
                subprocess.run(['systemctl', 'disable', '--now', 'roskompozor-probe'], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif Path('/etc/init.d/roskompozor-probe').exists():
                subprocess.run(['/etc/init.d/roskompozor-probe', 'disable'], check=False)
                subprocess.run(['/etc/init.d/roskompozor-probe', 'stop'], check=False)
    except BaseException:
        if (backup / 'program').exists():
            shutil.copytree(backup / 'program', app, dirs_exist_ok=True)
        if (backup / 'config.json').exists(): shutil.copy2(backup / 'config.json', conf / 'config.json')
        if (backup / 'service').exists(): shutil.copy2(backup / 'service', unit)
        if router:
            firewall = Path('/etc/nftables.d/90-roskompozor-probe.nft')
            subprocess.run(['nft', 'flush', 'chain', 'inet', 'fw4', 'probe_direct_counter'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['nft', 'flush', 'chain', 'inet', 'fw4', 'probe_local_api'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['nft', 'delete', 'chain', 'inet', 'fw4', 'probe_direct_counter'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['nft', 'delete', 'chain', 'inet', 'fw4', 'probe_local_api'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if (backup / 'firewall.nft').exists():
                shutil.copy2(backup / 'firewall.nft', firewall)
                subprocess.run(['nft', '-f', '-'], input='table inet fw4 {\n' + firewall.read_text() + '\n}\n', text=True)
            else: firewall.unlink(missing_ok=True)
        elif systemd and old_active:
            subprocess.run(['systemctl', 'daemon-reload']); subprocess.run(['systemctl', 'start', 'roskompozor-probe-next'])
        raise
    print(json.dumps({'installed': '2.0.0', 'service': 'roskompozor-probe-next', 'backup': str(backup), 'openwrt': router}))


if __name__ == '__main__':
    supplied = json.load(sys.stdin) if '--stdin-config' in sys.argv else None
    install(Path(__file__).resolve().parents[1], supplied)
