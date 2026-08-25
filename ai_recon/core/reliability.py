from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


async def retry_async(
    operation: Callable[[], Awaitable[T]],
    retries: int = 2,
    base_delay: float = 0.25,
    timeout: float | None = None,
) -> T:
    """Run an async operation with bounded exponential-backoff retries."""
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            result = operation()
            return await asyncio.wait_for(result, timeout=timeout) if timeout else await result
        except Exception as exc:
            last_error = exc
            if attempt >= retries:
                raise
            await asyncio.sleep(base_delay * (2**attempt))
    raise RuntimeError("retry operation failed") from last_error


class ConcurrencyLimiter:
    def __init__(self, limit: int) -> None:
        self._semaphore = asyncio.Semaphore(limit)

    async def run(self, operation: Callable[[], Awaitable[T]]) -> T:
        async with self._semaphore:
            return await operation()


class TTLCache:
    def __init__(self, ttl_seconds: float = 300) -> None:
        self.ttl_seconds = ttl_seconds
        self._entries: dict[str, tuple[float, object]] = {}

    def get(self, key: str) -> object | None:
        entry = self._entries.get(key)
        if not entry:
            return None
        created, value = entry
        if time.monotonic() - created > self.ttl_seconds:
            self._entries.pop(key, None)
            return None
        return value

    def set(self, key: str, value: object) -> None:
        self._entries[key] = (time.monotonic(), value)

    def clear(self) -> None:
        self._entries.clear()
