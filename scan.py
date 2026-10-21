"""Run this identical worker on every host; only DATABASE_URL is required."""
import asyncio
import json
import logging
import math
import time
import signal
import socket
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from uuid import uuid4

import aiohttp
import psycopg
import atlas_db as store

log = logging.getLogger('atlas')


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


async def lookup(session, ip):
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
                # Do not resume dispatch until this shared write succeeds.
                await database(store.cooldown, delay)
                log.warning('Shared cooldown %.1fs', delay)
            else:
                delay = 30
            retryable = response.status in {408, 429, 500, 502, 503, 504}
            log.warning('%s %s retryable=%s', ip, error, retryable)
            return ip, 'retry' if retryable else 'exhausted', None, error, delay
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        error = 'Request timeout' if isinstance(exc, asyncio.TimeoutError) else type(exc).__name__
        log.warning('%s %s; retry scheduled', ip, error)
        return ip, 'retry', None, error, 30


async def database(function, *args):
    # Bounded outage recovery. No credentials or connection exception strings logged.
    for attempt in range(6):
        try:
            return await asyncio.to_thread(function, *args)
        except psycopg.OperationalError:
            log.error('Database unavailable (%s), dispatch paused; attempt %s/6', function.__name__, attempt+1)
            if attempt == 5:
                raise RuntimeError('Database unavailable after bounded retries') from None
            await asyncio.sleep(min(15, 2**attempt))


class Worker:
    def __init__(self):
        self.instance = uuid4()
        self.hostname = socket.gethostname()
        self.job = None
        self.requests = self.saved = 0
        self.stop = asyncio.Event()
        self.db_lock = asyncio.Lock()
        self.lost = False
        self.counts = {}
        self.total = 0
        self.pause_until = 0
        self.last_health = 0

    async def progress(self):
        while not self.stop.is_set():
            log.info('HEARTBEAT host=%s instance=%s local requests=%s saved=%s | collection=%s target=%s cooldown=%.1fs health_age=%.1fs',
                     self.hostname, self.instance, self.requests, self.saved, self.counts, self.total,
                     max(0, self.pause_until-time.monotonic()),
                     time.monotonic()-self.last_health if self.last_health else 0)
            try:
                await asyncio.wait_for(self.stop.wait(), 15)
            except asyncio.TimeoutError:
                pass

    async def pulse(self):
        while not self.stop.is_set():
            try:
                async with self.db_lock:
                    counts, pause = await database(store.heartbeat, self.instance, self.job, self.requests, self.saved)
                self.counts = counts
                self.pause_until = time.monotonic()+pause
                self.last_health = time.monotonic()
            except store.LeaseLost:
                self.lost = True
                log.warning('Lease lost; stopping dispatch for job')
            except Exception:
                self.lost = True
                log.error('Heartbeat database failure; stopping dispatch')
            try:
                await asyncio.wait_for(self.stop.wait(), 15)
            except asyncio.TimeoutError:
                pass

    async def run(self):
        log.info('Starting host=%s instance=%s', self.hostname, self.instance)
        run = await database(store.register, self.instance, self.hostname)
        self.total = run['total']
        log.info('Startup hostname=%s instance=%s run=%s target=%s', self.hostname, self.instance, run['id'], run['total'])
        pulse = asyncio.create_task(self.pulse())
        progress = asyncio.create_task(self.progress())
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30, connect=10, sock_read=20),
                                             connector=aiohttp.TCPConnector(limit=4)) as session:
                while not self.stop.is_set():
                    async with self.db_lock:
                        self.job = await database(store.claim, run['id'], self.instance)
                        self.lost = False
                    if not self.job:
                        # No available work may mean leased work or durable retries are waiting.
                        try:
                            await asyncio.wait_for(self.stop.wait(), 3)
                        except asyncio.TimeoutError:
                            pass
                        continue
                    log.info('Claimed job=%s %s to %s', self.job['id'], self.job['first_ip'], self.job['last_ip'])
                    try:
                        while not self.stop.is_set() and not self.lost:
                            async with self.db_lock:
                                ips, wait = await database(store.reserve, self.job)
                            if wait:
                                await asyncio.sleep(wait)
                                continue
                            if not ips:
                                break
                            if self.stop.is_set() or self.lost:
                                break
                            self.requests += len(ips)
                            tasks = [asyncio.create_task(lookup(session, ip)) for ip in ips]
                            stopper = asyncio.create_task(self.stop.wait())
                            group = asyncio.gather(*tasks, return_exceptions=True)
                            await asyncio.wait([group, stopper], return_when=asyncio.FIRST_COMPLETED)
                            if self.stop.is_set():
                                for task in tasks:
                                    if not task.done():
                                        task.cancel()
                            results = await group
                            stopper.cancel()
                            await asyncio.gather(stopper, return_exceptions=True)
                            completed = [r for r in results if isinstance(r, tuple)]
                            if completed:
                                async with self.db_lock:
                                    await database(store.save, self.job, completed)
                                self.saved += len(completed)
                            failures = [r for r in results if isinstance(r, Exception)]
                            if failures:
                                raise failures[0]
                    except store.LeaseLost:
                        log.warning('Lease lost job=%s; stale results rejected', self.job['id'])
                    finally:
                        async with self.db_lock:
                            try:
                                await database(store.release, self.job)
                            except store.LeaseLost:
                                log.warning('Release rejected: lease no longer owned')
                            self.job = None
        finally:
            self.stop.set()
            pulse.cancel()
            progress.cancel()
            await asyncio.gather(pulse, progress, return_exceptions=True)
            try:
                await database(store.heartbeat, self.instance, None, self.requests, self.saved, 'stopped')
            except Exception:
                log.error('Could not record shutdown; worker health will become stale')
            log.info('Shutdown local requests=%s saved=%s', self.requests, self.saved)


async def run():
    worker = Worker()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, worker.stop.set)
    await worker.run()


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
