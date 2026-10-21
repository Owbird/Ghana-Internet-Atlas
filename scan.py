import asyncio
import ipaddress
import itertools
import json
import logging
import random
import sqlite3
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import aiohttp


SNAPSHOT_PATH = "ghana_routes.json"
DB_PATH = "ghana_internetdb.sqlite"
LOG_PATH = "scan.log"

BATCH_SIZE = 1_00
CONCURRENCY = 10
REQUESTS_PER_SECOND = 50
MAX_ATTEMPTS = 5
REQUEST_TIMEOUT = 30
HEARTBEAT_SECONDS = 15
COMMIT_EVERY = 100

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
    ],
)

log = logging.getLogger("atlas")


def duration(seconds):
    if seconds is None:
        return "unknown"

    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    return f"{minutes}m {seconds:02d}s"


def load_ranges():
    with open(SNAPSHOT_PATH, encoding="utf-8") as handle:
        snapshot = json.load(handle)

    networks = list(ipaddress.collapse_addresses(
        ipaddress.IPv4Network(prefix)
        for prefix in snapshot["ipv4_ranges"]
    ))

    total = sum(network.num_addresses for network in networks)

    log.info("Loaded %s IPv4 ranges", f"{len(networks):,}")
    log.info("Total addresses: %s", f"{total:,}")
    log.info(
        "Route window: %s to %s",
        snapshot.get("query_starttime", "unknown"),
        snapshot.get("query_endtime", "unknown"),
    )

    return networks, total


def open_database():
    connection = sqlite3.connect(DB_PATH, timeout=5)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS lookups (
            ip TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            payload TEXT,
            error TEXT,
            fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    connection.commit()
    return connection


def addresses(networks):
    for network in networks:
        for ip in network:
            yield str(ip)


def cached_addresses(db, batch):
    cached = set()

    # Stay below older SQLite builds' parameter limits.
    for offset in range(0, len(batch), 500):
        chunk = batch[offset:offset + 500]
        placeholders = ",".join("?" for _ in chunk)

        cached.update(
            row[0]
            for row in db.execute(
                f"""
                SELECT ip
                FROM lookups
                WHERE ip IN ({placeholders})
                  AND status IN ('ok', 'no_data')
                """,
                chunk,
            )
        )

    return cached


def retry_after_seconds(value, fallback):
    """Support Retry-After expressed as seconds or an HTTP date."""
    if not value:
        return fallback

    try:
        return max(0.0, float(value))
    except (ValueError, OverflowError):
        pass

    try:
        stamp = parsedate_to_datetime(value)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)

        return max(
            0.0,
            (stamp - datetime.now(timezone.utc)).total_seconds(),
        )
    except (TypeError, ValueError, OverflowError):
        return fallback


class Collector:
    def __init__(self, db, total):
        self.db = db
        self.total = total

        self.semaphore = asyncio.Semaphore(CONCURRENCY)
        self.rate_lock = asyncio.Lock()

        self.next_request = 0.0
        self.cooldown_until = 0.0
        self.started = time.monotonic()
        self.last_completion = self.started

        self.processed = 0
        self.skipped = 0
        self.found = 0
        self.missing = 0
        self.errors = 0

        self.attempts = 0
        self.in_flight = 0
        self.waiting_for_rate = 0
        self.retry_sleeping = 0
        self.retries = 0
        self.throttles = 0
        self.uncommitted = 0

        self.phase = "starting"
        self.active_tasks = set()

    def commit(self):
        if self.uncommitted:
            self.db.commit()
            self.uncommitted = 0

    def progress(self, heartbeat=False):
        now = time.monotonic()
        elapsed = now - self.started
        rate = self.processed / max(elapsed, 0.001)
        remaining = max(
            0, self.total - self.processed - self.skipped
        )
        eta = remaining / rate if rate else None
        cooldown = max(0.0, self.cooldown_until - now)

        log.info(
            "%s | %s/%s | found=%s no_data=%s errors=%s cached=%s | "
            "%.1f/s ETA=%s | active=%s requests=%s pacing=%s "
            "retry_sleep=%s | cooldown=%.1fs | last_result=%s ago | %s",
            "HEARTBEAT" if heartbeat else "PROGRESS",
            f"{self.processed + self.skipped:,}",
            f"{self.total:,}",
            f"{self.found:,}",
            f"{self.missing:,}",
            f"{self.errors:,}",
            f"{self.skipped:,}",
            rate,
            duration(eta),
            len(self.active_tasks),
            self.in_flight,
            self.waiting_for_rate,
            self.retry_sleeping,
            cooldown,
            duration(now - self.last_completion),
            self.phase,
        )

    async def pace(self):
        self.waiting_for_rate += 1

        try:
            async with self.rate_lock:
                while True:
                    now = time.monotonic()
                    scheduled = max(
                        self.next_request,
                        self.cooldown_until,
                    )
                    delay = scheduled - now

                    if delay <= 0:
                        self.next_request = (
                            now + 1 / REQUESTS_PER_SECOND
                        )
                        return

                    await asyncio.sleep(delay)

                    # Recheck because another response may have extended
                    # the cooldown while this coroutine was sleeping.
        finally:
            self.waiting_for_rate -= 1

    async def sleep_before_retry(self, ip, attempt):
        delay = min(30, 2 ** (attempt - 1)) + random.random()

        self.retries += 1
        self.retry_sleeping += 1

        log.warning(
            "%s | retry %s/%s in %.1fs",
            ip,
            attempt + 1,
            MAX_ATTEMPTS,
            delay,
        )

        try:
            await asyncio.sleep(delay)
        finally:
            self.retry_sleeping -= 1

    async def lookup(self, session, ip):
        last_error = "No attempt completed"

        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                async with self.semaphore:
                    await self.pace()
                    self.attempts += 1
                    self.in_flight += 1

                    try:
                        async with session.get(
                            f"https://internetdb.shodan.io/{ip}"
                        ) as response:
                            body = await response.text()

                            if response.status == 200:
                                data = json.loads(body)

                                if not isinstance(data, dict):
                                    raise ValueError(
                                        "Response JSON is not an object"
                                    )

                                return (
                                    ip,
                                    "ok",
                                    json.dumps(data),
                                    None,
                                )

                            if response.status == 404:
                                return ip, "no_data", None, None

                            # Keep errors on one log line.
                            snippet = " ".join(body[:200].split())
                            last_error = (
                                f"HTTP {response.status}: {snippet}"
                            )

                            if response.status == 429:
                                self.throttles += 1

                                delay = retry_after_seconds(
                                    response.headers.get("Retry-After"),
                                    min(60, 2 ** attempt),
                                )

                                self.cooldown_until = max(
                                    self.cooldown_until,
                                    time.monotonic() + delay,
                                )

                                log.warning(
                                    "%s | HTTP 429 | attempt %s/%s | "
                                    "GLOBAL PAUSE %.1fs remaining",
                                    ip,
                                    attempt,
                                    MAX_ATTEMPTS,
                                    max(
                                        0,
                                        self.cooldown_until
                                        - time.monotonic(),
                                    ),
                                )

                            elif response.status in {
                                408, 500, 502, 503, 504
                            }:
                                log.warning(
                                    "%s | %s | attempt %s/%s",
                                    ip,
                                    last_error,
                                    attempt,
                                    MAX_ATTEMPTS,
                                )

                            else:
                                log.error(
                                    "%s | non-retryable response | %s",
                                    ip,
                                    last_error,
                                )
                                return ip, "error", None, last_error

                    finally:
                        self.in_flight -= 1

            except asyncio.TimeoutError:
                last_error = (
                    f"Request timed out after {REQUEST_TIMEOUT}s"
                )
                log.warning(
                    "%s | TIMEOUT | attempt %s/%s",
                    ip,
                    attempt,
                    MAX_ATTEMPTS,
                )

            except (aiohttp.ClientError, ValueError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                log.warning(
                    "%s | %s | attempt %s/%s",
                    ip,
                    last_error,
                    attempt,
                    MAX_ATTEMPTS,
                )

            if attempt < MAX_ATTEMPTS:
                await self.sleep_before_retry(ip, attempt)

        log.error(
            "%s | exhausted %s attempts | %s",
            ip,
            MAX_ATTEMPTS,
            last_error,
        )
        return ip, "error", None, last_error

    async def lookup_and_save(self, session, ip):
        result = await self.lookup(session, ip)

        # No await between receiving a completed result and saving it.
        self.db.execute("""
            INSERT INTO lookups (ip, status, payload, error)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                status = excluded.status,
                payload = excluded.payload,
                error = excluded.error,
                fetched_at = CURRENT_TIMESTAMP
        """, result)

        status = result[1]

        self.processed += 1
        self.found += status == "ok"
        self.missing += status == "no_data"
        self.errors += status == "error"
        self.last_completion = time.monotonic()
        self.uncommitted += 1

        if self.uncommitted >= COMMIT_EVERY:
            self.commit()

        if self.processed % 100 == 0:
            self.progress()

    async def heartbeat(self):
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            self.commit()
            self.progress(heartbeat=True)

    async def collect(self, networks):
        timeout = aiohttp.ClientTimeout(
            total=REQUEST_TIMEOUT,
            connect=10,
            sock_read=20,
        )
        connector = aiohttp.TCPConnector(
            limit=CONCURRENCY,
            ttl_dns_cache=300,
        )

        log.info(
            "Starting | concurrency=%s target_rate=%s/s "
            "timeout=%ss max_attempts=%s",
            CONCURRENCY,
            REQUESTS_PER_SECOND,
            REQUEST_TIMEOUT,
            MAX_ATTEMPTS,
        )
        log.info(
            "Database=%s | log=%s | heartbeat=%ss",
            DB_PATH,
            LOG_PATH,
            HEARTBEAT_SECONDS,
        )

        pulse = asyncio.create_task(self.heartbeat())

        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
            ) as session:
                stream = addresses(networks)
                batch_number = 0

                while batch := list(
                    itertools.islice(stream, BATCH_SIZE)
                ):
                    batch_number += 1
                    self.phase = f"checking batch {batch_number}"

                    cached = cached_addresses(self.db, batch)
                    self.skipped += len(cached)
                    pending = [
                        ip for ip in batch if ip not in cached
                    ]

                    if not pending:
                        if batch_number % 100 == 0:
                            log.info(
                                "Resume: passed %s cached addresses",
                                f"{self.skipped:,}",
                            )
                        # Let heartbeat/cancellation run during resume.
                        await asyncio.sleep(0)
                        continue

                    log.info(
                        "BATCH %s | %s → %s | pending=%s cached=%s",
                        batch_number,
                        batch[0],
                        batch[-1],
                        len(pending),
                        len(cached),
                    )

                    self.phase = f"collecting batch {batch_number}"

                    tasks = {
                        asyncio.create_task(
                            self.lookup_and_save(session, ip)
                        )
                        for ip in pending
                    }

                    self.active_tasks = tasks
                    for task in tasks:
                        task.add_done_callback(
                            self.active_tasks.discard
                        )

                    try:
                        for task in asyncio.as_completed(tasks):
                            await task
                    finally:
                        # Stop remaining work before closing the session.
                        remaining_tasks = [
                            task for task in tasks if not task.done()
                        ]

                        if remaining_tasks:
                            log.info(
                                "Cancelling %s unfinished lookups",
                                len(remaining_tasks),
                            )
                            for task in remaining_tasks:
                                task.cancel()

                        # Retrieve every result/exception and allow
                        # cancellation cleanup to finish.
                        await asyncio.gather(
                            *tasks,
                            return_exceptions=True,
                        )
                        self.commit()
                        self.active_tasks = set()

                    log.info("BATCH %s complete", batch_number)

            self.phase = "finished"
            self.progress()
            log.info(
                "Collection finished | elapsed=%s attempts=%s "
                "retries=%s throttled_responses=%s",
                duration(time.monotonic() - self.started),
                f"{self.attempts:,}",
                f"{self.retries:,}",
                f"{self.throttles:,}",
            )

        except asyncio.CancelledError:
            log.warning(
                "Collection interrupted. Saving completed results."
            )
            raise

        finally:
            pulse.cancel()
            await asyncio.gather(pulse, return_exceptions=True)
            self.commit()


async def run(db, networks, total):
    collector = Collector(db, total)
    await collector.collect(networks)


def main():
    db = None

    try:
        networks, total = load_ranges()
        db = open_database()
        asyncio.run(run(db, networks, total))

    except KeyboardInterrupt:
        log.warning("Stopped by user. Completed results are saved.")

    except Exception:
        log.exception("Collector failed")
        return 1

    finally:
        if db is not None:
            try:
                db.commit()
                log.info("Saved database totals:")

                for status, count in db.execute("""
                    SELECT status, COUNT(*)
                    FROM lookups
                    GROUP BY status
                """):
                    log.info("  %s: %s", status, f"{count:,}")

            finally:
                db.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
