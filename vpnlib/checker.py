import asyncio
import json
import socket
import time
from pathlib import Path

import config


class Checker:
    def __init__(
        self,
        timeout: float = None,
        concurrency: int = None,
        retries: int = None,
        cache_path: Path = None,
        cache_ttl_hours: float = None,
        use_cache: bool = True,
    ):
        self.timeout = timeout or config.CHECK_TIMEOUT
        self.concurrency = concurrency or config.CHECK_CONCURRENCY
        self.retries = retries if retries is not None else config.CHECK_RETRIES
        self.cache_path = cache_path or (config.OUTPUT_DIR / "cache.json")
        self.cache_ttl = (cache_ttl_hours or config.CACHE_TTL_HOURS) * 3600
        self.use_cache = use_cache
        self._cache = {}
        self._load_cache()

    def _load_cache(self):
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._cache = data
        except Exception:
            self._cache = {}

    def save_cache(self):
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def _cache_hit(self, key):
        entry = self._cache.get(key)
        if not entry:
            return None
        try:
            if time.time() - float(entry.get("t", 0)) > self.cache_ttl:
                return None
            return entry
        except Exception:
            return None

    async def _tcp_check(self, host: str, port: int):
        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            latency = int((time.monotonic() - start) * 1000)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return "alive", latency
        except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return "dead", -1
        except socket.gaierror:
            return "unknown", -1
        except (OSError,) as e:
            errno = getattr(e, "errno", None) or 0
            if errno in (10049, 10060, 10061, 10064, 10065):  # unreachable / refused / reset
                return "dead", -1
            return "unknown", -1
        except asyncio.TimeoutError:
            return "unknown", -1
        except Exception:
            return "unknown", -1

    async def check_node(self, node):
        key = json.dumps(node.key, ensure_ascii=False)
        if self.use_cache:
            hit = self._cache_hit(key)
            if hit:
                node.status = hit.get("s", "unknown")
                node.latency_ms = int(hit.get("l", -1))
                return node
        status, latency = await self._tcp_check(node.host, node.port)
        if status == "unknown" and self.retries > 0:
            status, latency = await self._tcp_check(node.host, node.port)
        node.status = status
        node.latency_ms = latency
        self._cache[key] = {"s": status, "l": latency, "t": time.time()}
        return node

    async def check_all(self, nodes, progress_cb=None):
        sem = asyncio.Semaphore(self.concurrency)

        async def one(node):
            async with sem:
                result = await self.check_node(node)
                if progress_cb:
                    progress_cb(result)
                return result

        return await asyncio.gather(*[one(n) for n in nodes])
