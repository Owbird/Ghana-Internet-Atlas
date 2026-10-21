"""Run this identical worker on every host; only DATABASE_URL is required."""
import asyncio
import json
import logging
import math
import time
import queue
import signal
import socket
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from uuid import uuid4
from collections import deque

import aiohttp
import psycopg
import atlas_db as store

log = logging.getLogger('atlas')
CONCURRENCY = 10
PREPARE_BATCH = 32
SAVE_BATCH = 16
SAVE_INTERVAL = 1.0


def retry_after_seconds(value, fallback=60):
    try:
        seconds = float(value)
        return max(0, seconds) if math.isfinite(seconds) else fallback
    except (TypeError, ValueError, OverflowError):
        try:
            stamp = parsedate_to_datetime(value)
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            return max(0, (stamp-datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return fallback


async def lookup(session, ip, on_cooldown=None):
    try:
        async with session.get(f'https://internetdb.shodan.io/{ip}') as response:
            # Bound response memory, including malformed upstream responses.
            try:
                body = await response.content.readexactly(1_000_001)
            except asyncio.IncompleteReadError as exc:
                body = exc.partial
            if len(body) > 1_000_000:
                raise ValueError('Response exceeds 1 MB')
            if response.status == 200:
                payload = json.loads(body)
                if not isinstance(payload, dict):
                    raise ValueError('Expected JSON object')
                return ip, 'ok', payload, None, 0
            if response.status == 404:
                return ip, 'no_data', None, None, 0
            error = f'HTTP {response.status}: {body[:200].decode(errors="replace")}'
            if response.status == 429:
                delay = retry_after_seconds(response.headers.get('Retry-After'))
                if on_cooldown:
                    await on_cooldown(delay)
                log.warning('Host cooldown %.1fs', delay)
            else:
                delay = 30
            retryable = response.status in {408, 429, 500, 502, 503, 504}
            log.warning('%s %s retryable=%s', ip, error, retryable)
            return ip, 'retry' if retryable else 'exhausted', None, error, delay
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        error = 'Request timeout' if isinstance(exc, asyncio.TimeoutError) else type(exc).__name__
        log.warning('%s %s; retry scheduled', ip, error)
        return ip, 'retry', None, error, 30


class HostLimiter:
    """Cache only a few short-lived permits; check the local pause on every start."""
    def __init__(self, worker):
        self.worker = worker
        self.lock = asyncio.Lock()
        self.credits = 0
        self.expires = 0
        self.next_refill = 0
        self.pause_until = 0

    async def cooldown(self, seconds):
        self.pause_until = max(self.pause_until, time.monotonic()+seconds)
        self.credits = 0
        await self.worker.database(store.cooldown, self.worker.hostname, seconds)

    async def acquire(self):
        started = time.monotonic()
        try:
            async with self.lock:
                while True:
                    self.worker.check_dispatch()
                    if not self.worker.db_ok.is_set():
                        await asyncio.sleep(.1)
                        continue
                    pause = self.pause_until-time.monotonic()
                    if pause > 0:
                        await asyncio.sleep(min(pause, .25))
                        continue
                    if self.credits and time.monotonic() < self.expires:
                        self.credits -= 1
                        return
                    refill_wait = self.next_refill-time.monotonic()
                    if refill_wait > 0:
                        # Wait locally for the known allocation deadline, without DB polling.
                        await asyncio.sleep(min(refill_wait, .25))
                        continue
                    credits, wait, cooldown = await self.worker.database(
                        store.host_permits, self.worker.hostname)
                    self.pause_until = max(self.pause_until, time.monotonic()+cooldown)
                    self.credits = credits
                    self.expires = time.monotonic()+.5
                    self.next_refill = time.monotonic()+wait
        finally:
            self.worker.rate_seconds += time.monotonic()-started


class Worker:
    def __init__(self):
        self.instance = uuid4()
        self.hostname = socket.gethostname()
        self.job = None
        self.requests = self.saved = self.completed = self.skipped = 0
        self.stop = asyncio.Event()
        self.db_ok = asyncio.Event()
        self.db_ok.set()
        self.db_failures = 0
        self.lost = False
        self.counts = {}
        self.total = 0
        self.last_health = 0
        self.lease_deadline = 0
        self.http_seconds = self.db_seconds = self.rate_seconds = 0
        self.limiter = HostLimiter(self)

    async def database(self, function, *args):
        started = time.monotonic()
        failed = False
        try:
            for attempt in range(6):
                try:
                    operation = asyncio.create_task(asyncio.to_thread(function, *args))
                    try:
                        return await asyncio.shield(operation)
                    except asyncio.CancelledError:
                        # Finish the short transaction before returning its pooled connection.
                        await operation
                        raise
                except (psycopg.OperationalError, queue.Empty) as exc:
                    if not failed:
                        failed = True
                        self.db_failures += 1
                        self.db_ok.clear()
                    log.error('Database operation failed (%s): %s SQLSTATE=%s; dispatch paused; attempt %s/6',
                              function.__name__, type(exc).__name__, getattr(exc, 'sqlstate', None) or 'none', attempt+1)
                    if attempt == 5:
                        self.lost = True
                        raise RuntimeError(
                            f'Database {function.__name__} failed after bounded retries: '
                            f'{type(exc).__name__} SQLSTATE={getattr(exc, "sqlstate", None) or "none"}'
                        ) from None
                    await asyncio.sleep(min(15, 2**attempt))
        finally:
            if failed:
                self.db_failures -= 1
                if not self.db_failures and not self.lost:
                    self.db_ok.set()
            self.db_seconds += time.monotonic()-started

    def check_dispatch(self):
        if self.stop.is_set():
            raise asyncio.CancelledError()
        if self.lost or time.monotonic() >= self.lease_deadline:
            raise store.LeaseLost('Lease can no longer be confirmed')

    async def progress(self):
        previous, previous_completed = time.monotonic(), 0
        while not self.stop.is_set():
            now = time.monotonic()
            rate = (self.completed-previous_completed)/max(now-previous, .001)
            log.info('HEARTBEAT host=%s instance=%s local requests=%s saved=%s skipped=%s throughput=%.2f/s '
                     'cooldown=%.1fs http_s=%.1f db_s=%.1f pacing_s=%.1f | collection=%s target=%s health_age=%.1fs',
                     self.hostname, self.instance, self.requests, self.saved, self.skipped, rate,
                     max(0, self.limiter.pause_until-now), self.http_seconds, self.db_seconds, self.rate_seconds,
                     self.counts, self.total, now-self.last_health if self.last_health else 0)
            previous, previous_completed = now, self.completed
            try:
                await asyncio.wait_for(self.stop.wait(), 15)
            except asyncio.TimeoutError:
                pass

    async def pulse(self):
        while not self.stop.is_set():
            try:
                job = self.job
                counts, pause = await self.database(store.heartbeat, self.instance, job, self.requests, self.saved)
                self.counts = counts
                self.limiter.pause_until = max(self.limiter.pause_until, time.monotonic()+pause)
                self.last_health = time.monotonic()
                if job is self.job and job:
                    self.lease_deadline = time.monotonic()+60
            except store.LeaseLost:
                # A heartbeat already in flight may reference a just-released job.
                if job is self.job:
                    self.lost = True
                    log.warning('Lease lost; stopping dispatch for job')
            except Exception:
                self.lost = True
                self.db_ok.clear()
                log.error('Heartbeat database failure; stopping dispatch')
            try:
                await asyncio.wait_for(self.stop.wait(), 15)
            except asyncio.TimeoutError:
                pass

    async def request(self, session, ip):
        await self.limiter.acquire()
        # Neither queued work nor cached permits may outlive confirmed ownership.
        self.check_dispatch()
        if not self.db_ok.is_set():
            await self.db_ok.wait()
            self.check_dispatch()
        self.requests += 1
        started = time.monotonic()
        cooldown_db_time = 0

        async def pause(seconds):
            nonlocal cooldown_db_time
            start = time.monotonic()
            await self.limiter.cooldown(seconds)
            cooldown_db_time += time.monotonic()-start
        try:
            return await lookup(session, ip, pause)
        finally:
            self.http_seconds += time.monotonic()-started-cooldown_db_time

    async def collect_job(self, session):
        """Refill on FIRST_COMPLETED; slow responses never hold up faster slots."""
        pending = deque()
        prepared = set()
        active = set()
        results = []
        exhausted = False
        last_save = time.monotonic()

        async def flush():
            nonlocal last_save
            if results:
                await self.database(store.save, self.job, results)
                self.saved += len(results)
                results.clear()
            last_save = time.monotonic()

        try:
            while not self.stop.is_set() and not self.lost:
                self.check_dispatch()
                if results and (len(results) >= SAVE_BATCH or time.monotonic()-last_save >= SAVE_INTERVAL):
                    await flush()
                if not exhausted and len(pending) < CONCURRENCY:
                    rows = await self.database(store.prepare, self.job, prepared, PREPARE_BATCH)
                    if not rows:
                        exhausted = True
                    for row in rows:
                        pending.append(row['ip'])
                        prepared.add(row['ip'])
                while pending and len(active) < CONCURRENCY and self.db_ok.is_set():
                    active.add(asyncio.create_task(self.request(session, pending.popleft())))
                if not active:
                    if exhausted:
                        break
                    await asyncio.sleep(.1)
                    continue
                done, active = await asyncio.wait(active, timeout=.2, return_when=asyncio.FIRST_COMPLETED)
                errors = []
                for task in done:
                    if task.cancelled():
                        continue
                    if task.exception():
                        errors.append(task.exception())
                    else:
                        results.append(task.result())
                        self.completed += 1
                if errors:
                    raise errors[0]
            # Initial imports are skipped without consuming attempts or requesting HTTP.
            self.skipped += max(0, self.job['size']-len(prepared))
        finally:
            for task in active:
                task.cancel()
            finished = await asyncio.gather(*active, return_exceptions=True)
            for result in finished:
                if isinstance(result, tuple):
                    results.append(result)
                    self.completed += 1
            # Cancellation preserves every completed response that still has a valid lease.
            await flush()

    async def run(self):
        log.info('Starting host=%s instance=%s concurrency=%s', self.hostname, self.instance, CONCURRENCY)
        run = await self.database(store.register, self.instance, self.hostname)
        self.total = run['total']
        log.info('Joined run=%s target=%s; pacing/cooldown scope=hostname', run['id'], run['total'])
        pulse = asyncio.create_task(self.pulse())
        progress = asyncio.create_task(self.progress())
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30, connect=10, sock_read=20),
                                             connector=aiohttp.TCPConnector(limit=CONCURRENCY)) as session:
                while not self.stop.is_set():
                    self.job = await self.database(store.claim, run['id'], self.instance)
                    self.lost = False
                    if not self.job:
                        try:
                            await asyncio.wait_for(self.stop.wait(), 3)
                        except asyncio.TimeoutError:
                            pass
                        continue
                    self.lease_deadline = time.monotonic()+60
                    log.info('Claimed job=%s %s to %s', self.job['id'], self.job['first_ip'], self.job['last_ip'])
                    before = self.requests
                    try:
                        await self.collect_job(session)
                        log.info('Checkpoint job=%s requests=%s (existing results skipped)', self.job['id'], self.requests-before)
                    except store.LeaseLost:
                        log.warning('Lease lost job=%s; stale writes rejected', self.job['id'])
                    finally:
                        job, self.job = self.job, None
                        try:
                            await self.database(store.release, job)
                        except store.LeaseLost:
                            log.warning('Release rejected: lease no longer owned')
        finally:
            self.stop.set()
            # Let an in-flight renewal finish before returning pooled connections.
            progress.cancel()
            await asyncio.gather(pulse, progress, return_exceptions=True)
            try:
                await self.database(store.heartbeat, self.instance, None, self.requests, self.saved, 'stopped')
            except Exception:
                log.error('Could not record shutdown; worker health will become stale')
            log.info('Shutdown host=%s requests=%s saved=%s http_s=%.1f db_s=%.1f',
                     self.hostname, self.requests, self.saved, self.http_seconds, self.db_seconds)


async def run():
    worker = Worker()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, worker.stop.set)
    store.enable_pool()
    try:
        await worker.run()
    finally:
        store.close_pool()


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s',
                        handlers=[logging.StreamHandler(), logging.FileHandler('scan.log')])
    try:
        asyncio.run(run())
    except (ValueError, RuntimeError) as exc:
        log.error('%s', exc)
        return 1
    except Exception as exc:
        log.error('Worker stopped: %s (connection details omitted)', type(exc).__name__)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
