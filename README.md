# Ghana Internet Atlas

Ghana Internet Atlas maps Ghana's announced IP space and summarizes InternetDB
records by network operator. It combines RIPEstat routing data, Shodan InternetDB
lookups, and optional APNIC user estimates in a Next.js dashboard and standalone
HTML reports.

The collector runs across multiple hosts. PostgreSQL holds the queue,
leases, results, retry schedules and hostname-scoped request budgets. Every host runs
`scan.py`; there is no coordinator, broker or Docker dependency.

## Quick start

From the repository root, install the Python dependencies and configure your
PostgreSQL connection:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set `DATABASE_URL`, then initialize the database and start a run:

```bash
python atlas_db.py
python build_prefixes.py --activate
python scan.py
```

The worker keeps running until stopped with Ctrl+C. In another terminal, start
the dashboard:

```bash
cp .env ui/.env.local
cd ui
pnpm install
pnpm dev
```

Open [localhost:3000](http://localhost:3000) to explore the collected results.
Optionally run `python measure_asn.py` from the repository root with the Python
environment activated to add APNIC user estimates, or `python report.py` to
generate `ghana_report.html`.

For an existing collection, skip initialization and seeding and follow
[Contribute from any host](#contribute-from-any-host). For SQLite imports, read
[Prepare once, before starting workers](#prepare-once-before-starting-workers)
before launching a worker.

## Project structure

| Path | Purpose |
| --- | --- |
| `build_prefixes.py` | Fetch Ghana's ASNs and announced routes, then seed collection jobs. |
| `atlas_db.py`, `schema.sql` | Initialize PostgreSQL and manage runs and host request budgets. |
| `scan.py` | Collect InternetDB records with resumable, distributed workers. |
| `measure_asn.py` | Import APNIC user estimates by ASN. |
| `migrate.py` | Import results from a legacy SQLite database. |
| `report.py` | Generate a standalone HTML report. |
| `ui/` | Next.js, React, and TypeScript dashboard. |
| `tests/` | Collector unit tests and optional PostgreSQL integration tests. |

## Prerequisites

- Python 3 with `venv` and `pip`.
- Access to a PostgreSQL 14+ database shared by all workers.
- Node.js and pnpm for the optional web dashboard; the package manager version is
  declared in [`ui/package.json`](ui/package.json).
- Outbound HTTPS access to RIPEstat and Shodan InternetDB for collection, and
  APNIC Labs for user estimates.

## Install on every host

```bash
git clone https://github.com/Owbird/Ghana-Internet-Atlas
cd Ghana-Internet-Atlas
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set DATABASE_URL to your existing central PostgreSQL database.
```

`DATABASE_URL` is the only required environment variable. The process reads `.env`
automatically; environment variables take precedence. Do not commit `.env` or
connection strings. Use the same database on every host. PostgreSQL 14+ is required.
Schema setup needs permission to create tables, indexes, functions and triggers.

## Prepare once, before starting workers

Initialize the idempotent schema:

```bash
python atlas_db.py
```

Fetch Ghana ASNs and routes exclusively from RIPEstat's Ghana country resource
list, save `ghana_routes.json`, seed jobs and activate the run:

```bash
python build_prefixes.py --activate
```

Or seed the existing snapshot without any route HTTP requests:

```bash
python build_prefixes.py --snapshot ghana_routes.json --activate
```

Both commands print the run ID. Snapshot identity hashes normalized IPv4 lookup
ranges, original ASN/prefix relationships, and the route query window. Collection
timestamps, ASN display names, JSON ordering and duplicate entries do not affect
identity. Seeding the same snapshot again does not duplicate jobs or reset results.
Original announcements (including IPv6 and timelines) are stored separately from
the merged, deduplicated IPv4 lookup ranges. Jobs contain at most 256 addresses
and never cross a merged range boundary. Network and broadcast addresses are
included, matching the original collector. No APNIC ASN source is added.

Import legacy results **before starting any workers**. Substitute the printed ID:

```bash
python migrate.py --sqlite ghana_internetdb.sqlite --run 1
```

The importer opens SQLite in read-only mode and never changes or deletes it.
Existing `(run_id, ip)` rows are retained on repeated imports. Saved timestamps,
payloads, no-data results and errors are preserved. Legacy errors become retry
rows with one consumed attempt and are eligible for another attempt. Addresses
outside the selected run are excluded and reported. Malformed legacy payloads
are retained as JSON strings. Stop workers before importing; the importer refuses
runs with a recently live worker. Import is one transaction, so workers only see a
complete import.

At most one run can be active. Workers never create or activate runs. A different
snapshot can be seeded without `--activate`. To switch runs, stop workers, then:

```bash
python atlas_db.py --deactivate 1
python build_prefixes.py --snapshot another_snapshot.json --activate
```

Deactivation does not forcibly terminate already-running workers; stop them first.

## Contribute from any host

After installation and setting only `DATABASE_URL`:

```bash
python scan.py
```

Workers identify themselves with `socket.gethostname()` and a new UUID per
process, including multiple processes on one host. They automatically join the
single active run and exit clearly if none exists. Idle workers wait for jobs,
retries or leases to become available; stop them with Ctrl+C when done.

Claims use short `FOR UPDATE SKIP LOCKED` transactions committed before HTTP.
A job lease lasts 90 seconds and is renewed every 15 seconds. All job operations
check the lease owner and token; a worker whose lease expired cannot submit
results for reassigned work. Unfinished jobs become claimable after expiry.

HTTP concurrency is bounded at ten requests per worker. Slots refill as soon as a
request finishes, without waiting for slower responses. Attempts are prepared in
batches of 32; results are saved in batches of 16 or after one second. The worker
reuses a small pool of up to three PostgreSQL connections, with short transactions
and no transaction held open during an HTTP request.
Each attempt is recorded durably before dispatch, including a recovery deadline.
Successful records (`ok`), confirmed InternetDB misses (`no_data`) and exhausted
failures are terminal. Retryable failures retain their attempt count and next
eligible timestamp. A maximum of five attempts survives restarts. Non-retryable
HTTP failures become exhausted immediately. Interrupted attempts consume budget;
a crash can repeat a request but cannot duplicate an observation row. Workers skip
terminal rows and complete a job only when all addresses are terminal. Ctrl+C
stops dispatch, cancels pending requests, saves completed responses and releases
owned work where the database is available.

Each hostname defaults to **5 requests/second**, independent of other hosts.
The host rate and cooldown live in PostgreSQL so restarting cannot clear a pause
and processes on the same hostname share the budget. Change a particular host's
budget without adding required environment variables:

```bash
python atlas_db.py --host buffalo --rate 5
# Omitting --host uses socket.gethostname() on this machine.
```

Workers acquire small allocations of four permits, rather than one transaction
per HTTP request. Unused permits expire locally after half a second. HTTP 429
immediately clears that process's permit cache and pauses its dispatch, honoring
`Retry-After` seconds or HTTP dates. The pause is persisted for that hostname;
other processes on that hostname observe it on their next allocation or heartbeat.
At most a half-second of previously issued cached permits may still be used by
another process on the same host, and already-dispatched requests may finish.
Different hostnames continue independently. Provider limits still apply.

The additive host-state table is created automatically at worker registration.
No new setup command, required variable, run or queue reseed is needed for an
existing installation. **Restart all workers after updating**; old processes keep
the old global pacing behavior until restarted. The legacy global pacing table
is retained for compatibility but upgraded workers never consult it.

Requests time out after 30 seconds. Database connection and statement timeouts
are bounded; transient connection failures retry with bounded exponential backoff.
Without confirmed ownership, database health and host pacing permission, new
requests are not dispatched.
If recovery fails the worker exits and its lease expires. Logs go to the console
and `scan.log`, with a heartbeat every 15 seconds, separate local process counts,
collection-wide status counters, host throughput and remaining host cooldown.
`http_s`, `db_s` and `pacing_s` are cumulative operation-seconds spent awaiting
HTTP, database work (including pool/reconnect/backoff), and pacing respectively;
concurrent waits overlap, so their sum is not wall-clock elapsed time. There is no misleading
ETA during pauses. Counters are updated transactionally by observation triggers;
heartbeats do not count the observations table.

## Report

```bash
python report.py --output ghana_report.html
python report.py --run 1 --host-limit 2000 --max-ports 100 --output reports/run-1.html
```

The report uses a read-only, repeatable-read PostgreSQL transaction and a streaming
cursor; it writes only the local HTML output. It retains ports, CPE fingerprints,
tags, source-reported CVEs, host inspection/search, anomalous-host exclusion,
coverage and network summaries. It also shows contributing host/process IDs,
healthy/stale/stopped workers, durable retries/exhausted counts, and each host’s
request budget and cooldown. Process counters are separate from run counters.

ASN attribution uses the most-specific original announced IPv4 prefix covering
an address (longest-prefix match). If multiple ASNs announce that same prefix,
all are displayed, alongside saved ASN names. Broader announcements do not
receive addresses covered by more-specific announcements, so network totals do
not overlap. `no_data` means InternetDB has no record, not that an address is
offline. CVE associations are source labels, not confirmed exploitability.

Snapshots, databases, logs, generated reports, credentials and `.env` are ignored
by Git. Keep the original SQLite file as a backup after migration.

## Verification

Offline tests use mocked HTTP responses and database calls; they never load the
production URL or launch the collector:

```bash
python -m unittest discover -s tests -v
```

They cover continuous bounded concurrency, checkpoints and shutdown, lease-loss
dispatch prevention, host-only cooldowns, Retry-After formats, database outage
recovery, batching, and connection reuse/rollback/replacement. Optional PostgreSQL
integration tests use only an explicitly supplied direct (unpooled)
`TEST_DATABASE_URL` for a disposable test database, create an
isolated schema, and drop that schema afterward. They never fall back to `.env`:

```bash
TEST_DATABASE_URL=postgresql://... python -m unittest discover -s tests -v
```

No full InternetDB collection is used as a test.

## Web UI

The Next.js dashboard in `ui/` reads the active PostgreSQL collection run.

```bash
cp .env ui/.env
cd ui
pnpm install
pnpm dev
```

Open [localhost:3000](http://localhost:3000) after the development server starts.
Initialize the database and activate a collection run using the preparation steps
above before opening the dashboard. Run workers to populate its results.

For a production build:

```bash
cd ui
pnpm build
pnpm start
```

The database URL stays on the server. Refresh reloads current counts and
operator metadata. Initial operators and summary counts render on the server
without querying APNIC measurements. The operator panel loads APNIC data for the selected ASN
through `/api/atlas/apnic?asn=…`. Hosts load only after selecting an operator, through
`/api/atlas/hosts?asn=…&page=…`; the backend returns five rows per page, totals,
and navigation flags. Host search
matches IP addresses, hostnames, and tags; the operator filter matches names and
ASNs. Missing APNIC measurements display as unavailable. The API returns selected
host fields and omits vulnerability identifiers.

The landing overview compares announced IPv4 ranges, resolved lookups, records,
hit rates, APNIC estimates, and exposure for each ASN. All column headings sort;
APNIC user share is the default. APNIC summary estimates load separately after
the server-rendered overview. Selecting an operator loads its measurement and
paginated hosts, with top-port and tag counts alongside them.

National and per-ASN metrics use these definitions:

- Scanned: `ok` plus `no_data`; retries and exhausted failures are excluded.
- Hit rate: hosts with records / scanned addresses.
- Exposure rate: hosts with at least one selected port or tag / hosts with records.
- Selected ports: BGP 179, Telnet 23, FTP 21, MySQL 3306, SNMP 161, Winbox 8291.
- Selected tags: `eol-product`, `eol-os`, `database`, `vpn`, `self-signed`.

Repeated indicators count once per host. Overlapping announcements are merged
within each ASN for announced address totals. Observations belong to the most
specific prefix; ties use the lowest ASN. National counts include each address
once. The methodology panel explains CGNAT, estimate dates, source update cadence,
and Shodan licensing. No measurements or exposure rates establish exploitability.

Run UI metric checks with `node --test ui/tests/atlas-metrics.test.cjs` and type
checks with `pnpm --dir ui exec tsc --noEmit`.

## APNIC user estimates

Import the latest available estimates for Ghana with a 60-day averaging window:

```bash
python measure_asn.py
```

To request a particular measurement date or averaging window:

```bash
python measure_asn.py --country GH --date 2026-10-01 --window 60
```

The importer stores measurements in the same PostgreSQL database and updates
existing rows for the same country, date, window, and ASN. These estimates provide
context for operator comparisons; they do not change the RIPEstat collection scope.
