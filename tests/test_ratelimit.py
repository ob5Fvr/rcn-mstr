"""Per-host rate limiter."""
import asyncio
import time

import pytest

from rcnmstr.http import HostRateLimiter



async def test_rate_limit_spacing():
    rl = HostRateLimiter(rate=20, per_host=1)  # 20/s => 50ms apart
    t0 = time.monotonic()
    for _ in range(5):
        await rl.acquire("h")
        rl.release("h")
    dt = time.monotonic() - t0
    assert dt >= 0.18  # ~4 intervals of 50ms


async def test_per_host_concurrency_cap():
    rl = HostRateLimiter(rate=0, per_host=2)
    await rl.acquire("h")
    await rl.acquire("h")
    acquired_third = False

    async def third():
        nonlocal acquired_third
        await rl.acquire("h")
        acquired_third = True
    task = asyncio.ensure_future(third())
    await asyncio.sleep(0.05)
    assert not acquired_third   # blocked at cap=2
    rl.release("h")
    await asyncio.sleep(0.05)
    assert acquired_third
    rl.release("h")
    rl.release("h")
    task.cancel()


async def test_disabled_is_fast():
    rl = HostRateLimiter(rate=0, per_host=100)
    t0 = time.monotonic()
    for _ in range(50):
        await rl.acquire("h")
        rl.release("h")
    assert time.monotonic() - t0 < 0.2


async def test_independent_hosts():
    rl = HostRateLimiter(rate=5, per_host=1)
    t0 = time.monotonic()
    await rl.acquire("a"); rl.release("a")
    await rl.acquire("b"); rl.release("b")  # different host: not serialized with a
    assert time.monotonic() - t0 < 0.15
