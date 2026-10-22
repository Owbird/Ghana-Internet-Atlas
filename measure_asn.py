#!/usr/bin/env python3
"""Import APNIC Labs ad-based Users per AS estimates into PostgreSQL."""
import argparse
from datetime import date, datetime
import math
import re
import sys

import psycopg
from psycopg.types.json import Jsonb
import requests

import atlas_db

SOURCE = 'https://stats.labs.apnic.net/aspop/'

SCHEMA = """
CREATE TABLE IF NOT EXISTS asn_measurements (
 country text NOT NULL CHECK(country ~ '^[A-Z]{2}$'),
 measured_on date NOT NULL,
 window_days integer NOT NULL CHECK(window_days > 0),
 asn bigint NOT NULL CHECK(asn BETWEEN 1 AND 4294967295),
 rank integer NOT NULL CHECK(rank > 0),
 name text NOT NULL,
 estimated_users bigint NOT NULL CHECK(estimated_users >= 0),
 country_percent numeric NOT NULL CHECK(country_percent >= 0),
 internet_percent numeric NOT NULL CHECK(internet_percent >= 0),
 samples bigint NOT NULL CHECK(samples >= 0),
 source_url text NOT NULL,
 metadata jsonb NOT NULL,
 payload jsonb NOT NULL,
 fetched_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(country, measured_on, window_days, asn)
);
"""


def parse_measurements(document, country, window, requested_date=None):
    """Validate the complete export before opening a database transaction."""
    if not isinstance(document, dict):
        raise ValueError('APNIC export must be an object')
    measured_on = datetime.strptime(document['Date'], '%d/%m/%Y').date()
    if document['Window'] != f'{window} Days':
        raise ValueError('APNIC returned a different averaging window')
    if requested_date and measured_on != requested_date:
        raise ValueError('APNIC returned a different measurement date')
    rows = document['Data']
    if not isinstance(rows, list) or not rows:
        raise ValueError('APNIC returned no ASN measurements')
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or row.get('CC') != country:
            raise ValueError('APNIC returned an unexpected country or row')
        for key in ('AS', 'rank', 'Users', 'Samples'):
            value = row[key]
            minimum = 1 if key in ('AS', 'rank') else 0
            if type(value) is not int or value < minimum:
                raise ValueError(f'Invalid {key} in APNIC export')
        if row['AS'] > 4294967295 or row['AS'] in seen:
            raise ValueError('Invalid or duplicate ASN in APNIC export')
        seen.add(row['AS'])
        if not isinstance(row['Description'], str):
            raise ValueError('Invalid ASN description')
        for key in ('Percent of CC Pop', 'Percent of Internet'):
            value = row[key]
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError(f'Invalid {key} in APNIC export')
    return measured_on, rows


def save_measurements(document, country, window, source_url, requested_date=None):
    measured_on, rows = parse_measurements(document, country, window, requested_date)
    metadata = {key: value for key, value in document.items() if key != 'Data'}
    with atlas_db.connect() as db:
        db.execute('SELECT pg_advisory_xact_lock(42178504)')
        db.execute(SCHEMA)
        with db.cursor() as cursor:
            cursor.executemany('''INSERT INTO asn_measurements
                (country,measured_on,window_days,asn,rank,name,estimated_users,
                 country_percent,internet_percent,samples,source_url,metadata,payload)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(country,measured_on,window_days,asn) DO UPDATE SET
                rank=excluded.rank,name=excluded.name,estimated_users=excluded.estimated_users,
                country_percent=excluded.country_percent,internet_percent=excluded.internet_percent,
                samples=excluded.samples,source_url=excluded.source_url,metadata=excluded.metadata,
                payload=excluded.payload,fetched_at=now()''',
                [(country, measured_on, window, row['AS'], row['rank'], row['Description'],
                  row['Users'], row['Percent of CC Pop'], row['Percent of Internet'],
                  row['Samples'], source_url, Jsonb(metadata), Jsonb(row)) for row in rows])
    return measured_on, len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--country', default='GH', type=str.upper, help='Country code (default: GH)')
    parser.add_argument('--date', type=date.fromisoformat, help='Measurement date YYYY-MM-DD (default: latest available)')
    parser.add_argument('--window', type=int, default=60, help='Averaging window in days (default: 60)')
    args = parser.parse_args()
    if not re.fullmatch('[A-Z]{2}', args.country) or args.window < 1:
        parser.error('Use a two-letter country code and positive window')
    params = dict(cc=args.country, ww=args.window, ff=3, rr=1, xx='t')
    if args.date:
        params['dd'] = args.date.strftime('%d/%m/%Y')
    try:
        response = requests.get(SOURCE, params=params, timeout=(10, 60))
        response.raise_for_status()
        measured_on, count = save_measurements(response.json(), args.country, args.window,
                                               response.url, args.date)
    except (requests.RequestException, ValueError, KeyError, TypeError, OSError, psycopg.Error) as exc:
        print(f'ASN measurement import failed ({type(exc).__name__}); check APNIC availability, export format and database configuration.', file=sys.stderr)
        return 1
    print(f'Saved {count} APNIC ASN measurements for {args.country}, {measured_on} ({args.window}-day window).')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
