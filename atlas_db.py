"""Small PostgreSQL coordination helpers. Each operation commits before returning."""
import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
from uuid import uuid4

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

TERMINAL = ('ok', 'no_data', 'exhausted')
LEASE_SECONDS = 90
MAX_ATTEMPTS = 5


class LeaseLost(RuntimeError):
    pass


def connect():
    load_dotenv()
    url = os.getenv('DATABASE_URL')
    if not url:
        raise ValueError('Set DATABASE_URL in .env before continuing.')
    db = psycopg.connect(url, row_factory=dict_row, connect_timeout=5, prepare_threshold=None)
    # Transaction-local settings also work with transaction-mode poolers.
    try:
        db.execute("SET LOCAL statement_timeout = '10s'")
        db.execute("SET LOCAL lock_timeout = '5s'")
    except Exception:
        db.close()
        raise
    return db


def initialize():
    with connect() as db:
        db.execute('SELECT pg_advisory_xact_lock(42178501)')
        db.execute(Path(__file__).with_name('schema.sql').read_text())


def selected_run(db, run_id=None):
    rows = db.execute('SELECT * FROM runs WHERE id=%s' if run_id else
                      'SELECT * FROM runs WHERE active', (run_id,) if run_id else ()).fetchall()
    if len(rows) != 1:
        raise ValueError('Expected exactly one selected/active run; seed and activate a run first.')
    return rows[0]


def normalized(snapshot):
    """Ignore fetch timestamps, names and ordering; retain scope, origins and query window."""
    ranges = list(ipaddress.collapse_addresses(
        ipaddress.IPv4Network(p) for p in snapshot['ipv4_ranges']))
    origins = sorted({(int(asn), str(ipaddress.ip_network(e['prefix'])))
                      for asn, entries in snapshot.get('asn_prefixes', {}).items()
                      for e in entries})
    content = {'ranges': [str(n) for n in ranges], 'origins': origins,
               'start': snapshot.get('query_starttime'), 'end': snapshot.get('query_endtime')}
    digest = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return digest, ranges


def seed(snapshot, activate=False):
    digest, ranges = normalized(snapshot)
    with connect() as db:
        db.execute('SELECT pg_advisory_xact_lock(42178502)')
        run = db.execute("""INSERT INTO runs(snapshot_hash,snapshot,total) VALUES(%s,%s,%s)
            ON CONFLICT(snapshot_hash) DO UPDATE SET snapshot_hash=excluded.snapshot_hash RETURNING id""",
            (digest, Jsonb(snapshot), sum(n.num_addresses for n in ranges))).fetchone()['id']
        with db.cursor() as cursor:
            cursor.executemany(
                "INSERT INTO routes VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                ((run, int(asn), snapshot.get('asn_names', {}).get(str(asn)),
                  str(ipaddress.ip_network(entry['prefix'])), Jsonb(entry))
                 for asn, entries in snapshot.get('asn_prefixes', {}).items()
                 for entry in entries),
            )
        for network in ranges:
            db.execute('INSERT INTO lookup_ranges VALUES(%s,%s) ON CONFLICT DO NOTHING', (run, str(network)))
            first, end = int(network.network_address), int(network.broadcast_address)
            with db.cursor() as cursor:
                cursor.executemany(
                    """INSERT INTO jobs(run_id,first_ip,last_ip,size) VALUES(%s,%s,%s,%s)
                    ON CONFLICT DO NOTHING""",
                    ((run, str(ipaddress.IPv4Address(start)),
                      str(ipaddress.IPv4Address(min(start+255, end))), min(256, end-start+1))
                     for start in range(first, end+1, 256)),
                )
        if activate:
            existing = db.execute('SELECT id FROM runs WHERE active').fetchall()
            if existing and existing[0]['id'] != run:
                raise ValueError('Another run is active; explicitly deactivate it before activating this run.')
            db.execute('UPDATE runs SET active=true WHERE id=%s', (run,))
    return run


def register(instance, hostname):
    with connect() as db:
        run = selected_run(db)
        db.execute('SELECT id FROM runs WHERE id=%s FOR SHARE', (run['id'],))
        db.execute('INSERT INTO workers(instance,hostname,run_id) VALUES(%s,%s,%s) ON CONFLICT(instance) DO NOTHING',
                   (instance, hostname, run['id']))
        return run


def claim(run, instance):
    with connect() as db:
        db.execute('SELECT id FROM runs WHERE id=%s FOR SHARE', (run,))
        return db.execute('''WITH candidate AS (
            SELECT id FROM jobs WHERE run_id=%s AND NOT done AND ready_at<=now()
            AND (owner IS NULL OR lease_until<=now()) ORDER BY ready_at,id
            FOR UPDATE SKIP LOCKED LIMIT 1)
            UPDATE jobs SET owner=%s, token=%s, lease_until=now()+interval '90 seconds'
            FROM candidate WHERE jobs.id=candidate.id RETURNING jobs.*''',
            (run, instance, uuid4())).fetchone()


def fence(db, job):
    row = db.execute('''SELECT * FROM jobs WHERE id=%s AND owner=%s AND token=%s
        AND lease_until>clock_timestamp() AND NOT done FOR UPDATE''',
        (job['id'], job['owner'], job['token'])).fetchone()
    if not row:
        raise LeaseLost('Job lease expired or was reassigned')


def heartbeat(instance, job, requests, saved, state='running'):
    with connect() as db:
        if job:
            fence(db, job)
            db.execute("UPDATE jobs SET lease_until=now()+interval '90 seconds' WHERE id=%s", (job['id'],))
        db.execute('UPDATE workers SET heartbeat=now(),state=%s,requests=%s,saved=%s WHERE instance=%s',
                   (state, requests, saved, instance))
        counts = db.execute('SELECT status,count FROM run_counts WHERE run_id=(SELECT run_id FROM workers WHERE instance=%s)', (instance,)).fetchall()
        cooldown = db.execute('SELECT greatest(0,extract(epoch FROM cooldown_until-now())) AS seconds FROM pacing WHERE id=1').fetchone()
        return {r['status']: r['count'] for r in counts}, float(cooldown['seconds'])


def reserve(job, limit=4):
    """Allocate a small immediate wave, recording attempts before HTTP. No future permits."""
    with connect() as db:
        fence(db, job)
        pace = db.execute('SELECT *,now() AS current FROM pacing WHERE id=1 FOR UPDATE').fetchone()
        wait = (max(pace['next_at'], pace['cooldown_until'])-pace['current']).total_seconds()
        if wait > 0:
            return [], min(wait, 1.0)
        rows = db.execute('''SELECT host(a.ip) AS ip FROM generate_series(0,%s) n
            CROSS JOIN LATERAL (SELECT %s::inet+n AS ip) a
            LEFT JOIN observations o ON o.ip=a.ip AND o.run_id=%s
            WHERE
            (o.status IS NULL OR (o.status='retry' AND o.next_retry<=now() AND o.attempts<%s))
            ORDER BY a.ip LIMIT %s''', (job['size']-1, str(job['first_ip']), job['run_id'], MAX_ATTEMPTS, limit)).fetchall()
        # A run-qualified join is essential when the same IP occurs in older runs.
        ips = [r['ip'] for r in rows]
        for ip in ips:
            db.execute('''INSERT INTO observations(run_id,ip,status,attempts,next_retry,worker)
                VALUES(%s,%s,'retry',1,now()+interval '45 seconds',%s)
                ON CONFLICT(run_id,ip) DO UPDATE SET attempts=observations.attempts+1,
                next_retry=now()+interval '45 seconds', worker=excluded.worker''',
                (job['run_id'], ip, job['owner']))
        if ips:
            db.execute("UPDATE pacing SET next_at=now()+(%s/rate)*interval '1 second' WHERE id=1", (len(ips),))
        return ips, 0


def save(job, results):
    with connect() as db:
        fence(db, job)
        for ip, status, payload, error, delay in results:
            row = db.execute('SELECT attempts FROM observations WHERE run_id=%s AND ip=%s', (job['run_id'], ip)).fetchone()
            if status == 'retry' and row['attempts'] >= MAX_ATTEMPTS:
                status = 'exhausted'
            db.execute('''UPDATE observations SET status=%s,payload=%s,error=%s,
                fetched_at=now(),next_retry=now()+%s*interval '1 second'
                WHERE run_id=%s AND ip=%s''',
                (status, Jsonb(payload) if payload is not None else None, error,
                 delay, job['run_id'], ip))


def cooldown(seconds):
    with connect() as db:
        db.execute("UPDATE pacing SET cooldown_until=greatest(cooldown_until,clock_timestamp()+%s*interval '1 second') WHERE id=1", (seconds,))


def release(job):
    with connect() as db:
        fence(db, job)
        # An attempt interrupted by a crash still consumes its durable budget.
        db.execute('''UPDATE observations SET status='exhausted',error=coalesce(error,'Attempt interrupted')
            WHERE run_id=%s AND ip BETWEEN %s AND %s AND status='retry'
            AND attempts>=%s AND next_retry<=now()''',
            (job['run_id'], job['first_ip'], job['last_ip'], MAX_ATTEMPTS))
        state = db.execute('''SELECT count(*) FILTER(WHERE status IN ('ok','no_data','exhausted')) AS terminal,
            min(next_retry) FILTER(WHERE status='retry') AS ready FROM observations
            WHERE run_id=%s AND ip BETWEEN %s AND %s''',
            (job['run_id'], job['first_ip'], job['last_ip'])).fetchone()
        db.execute('''UPDATE jobs SET owner=NULL,token=NULL,lease_until=NULL,done=%s,
            ready_at=coalesce(%s,now()) WHERE id=%s''',
            (state['terminal'] == job['size'], state['ready'], job['id']))


def main():
    parser = argparse.ArgumentParser(description='Initialize the schema or manage run activation.')
    parser.add_argument('--deactivate', type=int)
    parser.add_argument('--rate', type=float, help='Set the shared aggregate requests/second budget')
    args = parser.parse_args()
    initialize()
    with connect() as db:
        if args.deactivate:
            db.execute('UPDATE runs SET active=false WHERE id=%s', (args.deactivate,))
        if args.rate is not None:
            if not math.isfinite(args.rate) or args.rate <= 0:
                parser.error('--rate must be positive')
            db.execute('UPDATE pacing SET rate=%s WHERE id=1', (args.rate,))
    print('Schema ready.')


if __name__ == '__main__':
    main()
