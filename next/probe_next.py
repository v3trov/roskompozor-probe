#!/usr/bin/env python3
"""Isolated preview Probe. HTTPS pull transport and a durable result outbox."""
from __future__ import annotations

import concurrent.futures
import json
import logging
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import network

LOG = logging.getLogger('probe-next')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Api:
    def __init__(self, config):
        parsed = urllib.parse.urlsplit(config['server'])
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in ('', '/')):
            raise ValueError('HTTPS API origin required')
        self.origin, self.key = config['server'].rstrip('/'), config['api_key']
        self.timeout = max(2, min(30, float(config.get('request_timeout', 12))))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, payload=None):
        route, _, query = path.partition('?')
        if route not in ('/api/probe/checks', '/api/probe/results') or (query and
                (route != '/api/probe/checks' or query not in ('limit=1', 'limit=2'))):
            raise ValueError('invalid API path')
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(self.origin + path, data=body, headers={
            'Authorization': 'Bearer ' + self.key, 'Content-Type': 'application/json',
            'User-Agent': 'RoskompozorProbe/' + network.VERSION})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(1048577)
                if len(raw) > 1048576:
                    raise ValueError('oversized API response')
                reply = json.loads(raw)
        except urllib.error.HTTPError as error:
            error.close()
            raise
        if not isinstance(reply, dict):
            raise ValueError('invalid API response')
        return reply


class Queue:
    def __init__(self, path):
        self.db = sqlite3.connect(str(path))
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS jobs('
                        'id TEXT PRIMARY KEY,item TEXT NOT NULL,created REAL NOT NULL,'
                        "state TEXT NOT NULL DEFAULT 'pending',result TEXT)")
        self.db.execute("UPDATE jobs SET state='pending' WHERE state='running'")
        self.db.commit()

    def add(self, items):
        if not isinstance(items, list) or len(items) > 50:
            raise ValueError('invalid jobs response')
        validated = []
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get('id'), (str, int)):
                raise ValueError('invalid job')
            key = str(item['id'])
            if not key or len(key) > 128 or len(json.dumps(item)) > 4096:
                raise ValueError('oversized job')
            # Validation happens before persisting; bad targets never reach a child.
            network.legacy.normalize_host(item['target'])
            validated.append((key, json.dumps(item), time.time()))
        with self.db:
            self.db.executemany('INSERT OR IGNORE INTO jobs(id,item,created) VALUES(?,?,?)', validated)

    def next(self, count):
        rows = self.db.execute("SELECT id,item FROM jobs WHERE state='pending' ORDER BY created,id LIMIT ?", (count,)).fetchall()
        with self.db:
            self.db.executemany("UPDATE jobs SET state='running' WHERE id=?", [(row[0],) for row in rows])
        return [(key, json.loads(item)) for key, item in rows]

    def finish(self, key, result):
        raw = json.dumps(result, ensure_ascii=True)
        if len(raw) > 131072:
            result = {'ok': False, 'error_type': 'report_too_large'}
        with self.db:
            self.db.execute("UPDATE jobs SET result=?,state='outbox' WHERE id=?", (json.dumps(result), key))

    def submit(self, api):
        for key, raw in self.db.execute("SELECT id,result FROM jobs WHERE state='outbox' ORDER BY created").fetchall():
            reply = api.request('/api/probe/results', {'results': [{'check_id': key, 'result': json.loads(raw)}]})
            values = [reply.get(name) for name in ('accepted', 'duplicates', 'rejected')]
            if any(type(v) is not int or v < 0 for v in values) or sum(values) != 1:
                raise ValueError('invalid acknowledgement; outbox retained')
            with self.db:
                self.db.execute('UPDATE jobs SET state=? WHERE id=?', ('rejected' if values[2] else 'sent', key))
            if values[2]:
                LOG.warning('API rejected one report; retained for inspection')

    def pending(self):
        return self.db.execute("SELECT count(*) FROM jobs WHERE state IN ('pending','running','outbox')").fetchone()[0]

    def prune(self):
        # Keep recent diagnostic history; never delete an unsent production report.
        with self.db:
            self.db.execute("DELETE FROM jobs WHERE state IN ('sent','shadow','rejected') AND "
                            "(created<? OR id IN (SELECT id FROM jobs WHERE state IN ('sent','shadow','rejected') "
                            'ORDER BY created DESC LIMIT -1 OFFSET 500))', (time.time() - 7 * 86400,))


def execute_job(item, controls, timeout=65):
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--job'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=os.name != 'nt')
    try:
        out, err = process.communicate(json.dumps({'item': item, 'controls': controls}), timeout=timeout)
        if process.returncode or len(out) > 131072:
            return {'ok': False, 'error_type': 'measurement_error'}
        result = json.loads(out)
        if not isinstance(result, dict) or type(result.get('ok')) is not bool:
            raise ValueError('invalid child report')
        return result
    except subprocess.TimeoutExpired:
        if os.name == 'nt':
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        return {'ok': False, 'error_type': 'timeout', 'summary': 'Measurement deadline exceeded'}


def load_config(path):
    config = json.loads(path.read_text())
    if config.get('mode') not in ('shadow', 'api'):
        raise ValueError('explicit shadow/api mode required')
    config['parallel'] = max(1, min(2, int(config.get('parallel', 1))))
    config['interval'] = max(60, min(3600, int(config.get('interval', 300))))
    config['poll_interval'] = max(5, min(3600, int(config.get('poll_interval', 5))))
    if config['mode'] == 'api':
        if config.get('server') != 'https://roskompozor.ru':
            raise ValueError('Only the Roskompozor API is supported')
        if not isinstance(config.get('api_key'), str) or len(config['api_key']) != 68 or not config['api_key'].startswith('rkp_'):
            raise ValueError('Invalid API key')
    if len(config.get('controls', [])) > 2:
        raise ValueError('at most two owned controls')
    for control in config.get('controls', []):
        if not network.legacy.public_ip(control['ip']) or control.get('port', 443) != 443:
            raise ValueError('invalid public control')
    return config


def daemon(config):
    if config.get('direct_dns'):
        os.environ['ROSKOMPOZOR_DIRECT_DNS'] = '1'
        network.socket.getaddrinfo = network.direct_getaddrinfo
    state = Path(config['state_dir'])
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    queue = Queue(state / 'queue.sqlite')
    api = Api(config) if config['mode'] == 'api' else None
    LOG.info('Started %s mode=%s', network.VERSION, config['mode'])
    while True:
        try:
            if api:
                queue.submit(api)
                if not queue.pending():
                    queue.add(api.request('/api/probe/checks?limit=' + str(config['parallel'])).get('checks'))
            else:
                bucket = int(time.time()) // config['interval']
                queue.add([{'id': f'shadow-{bucket}-{index}', 'target': target,
                    'type': 'domain', 'ports': []} for index, target in enumerate(config['targets'])])
            jobs = queue.next(config['parallel'])
            if jobs:
                with concurrent.futures.ThreadPoolExecutor(max_workers=config['parallel']) as executor:
                    futures = {executor.submit(execute_job, item, config.get('controls', [])): key for key, item in jobs}
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            result = future.result()
                        except Exception:
                            result = {'ok': False, 'error_type': 'measurement_error'}
                        queue.finish(futures[future], result)
                        if api:
                            try:
                                queue.submit(api)  # Do not wait for slower jobs to finish.
                            except Exception as error:
                                LOG.warning('Outbox retained: %s', type(error).__name__)
                        else:
                            with queue.db:
                                queue.db.execute("UPDATE jobs SET state='shadow' WHERE id=?", (futures[future],))
                        LOG.info('Completed one measurement')
            queue.prune()
            if not jobs:
                time.sleep(config['poll_interval'] if api else 15)
        except Exception as error:
            # Never log bearer keys, configuration or full request exceptions.
            LOG.warning('Iteration failed: %s', type(error).__name__)
            time.sleep(10)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--validate-config':
        load_config(Path(sys.argv[2]))
    elif len(sys.argv) == 2 and sys.argv[1] == '--job':
        try:
            payload = json.load(sys.stdin)
            print(json.dumps(network.measure(payload['item'], payload.get('controls', [])), ensure_ascii=True))
        except Exception as error:
            print(json.dumps({'ok': False, 'error_type': network.legacy.error_type(error)}))
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
        daemon(load_config(Path(sys.argv[1])))
