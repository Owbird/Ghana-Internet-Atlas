"""Import legacy SQLite results without modifying the source. Run before workers."""
import argparse
import ipaddress
import json
import sqlite3
import psycopg
from datetime import datetime, timezone
from pathlib import Path

from psycopg.types.json import Jsonb
import atlas_db as store


def migrate(path, run_id):
    imported = excluded = existing = 0
    with sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True) as source, store.connect() as db:
        source.execute('PRAGMA query_only=ON')
        source.execute('BEGIN')
        run = store.selected_run(db, run_id)
        db.execute('SELECT id FROM runs WHERE id=%s FOR UPDATE', (run_id,))
        if db.execute("SELECT 1 FROM workers WHERE run_id=%s AND state='running' AND heartbeat>now()-interval '90 seconds' LIMIT 1", (run_id,)).fetchone():
            raise ValueError('Stop all workers before migration, then wait for their leases to expire.')
        networks = [ipaddress.ip_network(r['prefix']) for r in db.execute('SELECT prefix FROM lookup_ranges WHERE run_id=%s', (run_id,))]
        pending = []

        def flush():
            nonlocal imported, existing
            with db.cursor() as cursor:
                cursor.executemany("""INSERT INTO observations(run_id,ip,status,attempts,payload,error,fetched_at)
                    VALUES(%s,%s,%s,1,%s,%s,%s) ON CONFLICT DO NOTHING""", pending)
                imported += cursor.rowcount
                existing += len(pending)-cursor.rowcount
            pending.clear()

        for ip, status, raw, error, stamp in source.execute('SELECT ip,status,payload,error,fetched_at FROM lookups'):
            try:
                address = ipaddress.IPv4Address(ip)
                if not any(address in network for network in networks):
                    raise ValueError('Outside scope')
            except ValueError:
                excluded += 1
                continue
            payload = None
            if raw is not None:
                try:
                    payload = json.loads(raw)
                except (ValueError, TypeError):
                    payload = raw  # Preserve malformed legacy payload as a JSONB string.
            mapped = status if status in ('ok', 'no_data') else 'retry'
            fetched = datetime.fromisoformat(stamp) if stamp else run['created_at']
            if fetched.tzinfo is None:
                fetched = fetched.replace(tzinfo=timezone.utc)
            pending.append((run_id, str(address), mapped, Jsonb(payload) if raw is not None else None,
                            error, fetched))
            if len(pending) >= 500:
                flush()
        if pending:
            flush()
        # Imported terminal rows are skipped by workers; jobs finalize when claimed.
    return {'imported': imported, 'already_present': existing, 'excluded': excluded}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sqlite', type=Path, default=Path('ghana_internetdb.sqlite'))
    parser.add_argument('--run', type=int, required=True)
    args = parser.parse_args()
    try:
        print(migrate(args.sqlite, args.run))
    except ValueError as exc:
        parser.exit(1, f'{exc}\n')
    except (sqlite3.Error, psycopg.Error) as exc:
        parser.exit(1, f'Migration failed: {type(exc).__name__}; check database access.\n')


if __name__ == '__main__':
    main()
