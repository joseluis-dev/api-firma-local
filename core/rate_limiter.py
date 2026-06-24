"""Rate limiter en memoria (por IP de loopback).

Suficiente para uso local: protege contra fuerza bruta de PIN sin
necesidad de Redis.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict, Tuple


class RateLimiter:
    """Token-bucket por clave (ip + endpoint)."""

    def __init__(self, max_requests: int, window_seconds: int = 60) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._buckets: Dict[Tuple[str, str], Deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, endpoint: str) -> bool:
        """Registra un hit. Devuelve True si esta dentro del limite."""
        bucket_key = (endpoint, key)
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.setdefault(bucket_key, deque())
            cutoff = now - self._window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self._max:
                return False
            bucket.append(now)
            return True

    def reset(self, key: str, endpoint: str) -> None:
        with self._lock:
            self._buckets.pop((endpoint, key), None)
