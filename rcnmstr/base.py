"""Module base class + auto-registry."""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Type

REGISTRY: Dict[str, Type["Module"]] = {}


class Module:
    name: str = ""
    phase: int = 50
    mode: str = "normal"        # minimum run mode: passive | normal | deep
    loop: bool = False          # re-run in every feedback round
    once: bool = True           # run only in the first round (ignored if loop)
    final: bool = False         # run after the feedback loop ends
    description: str = ""
    default: bool = True        # enabled unless explicitly selected with --modules

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        if cls.name:
            REGISTRY[cls.name] = cls

    def __init__(self):
        self.log = logging.getLogger(f"rcnmstr.{self.name}")
        self.done = set()

    async def run(self, ctx) -> None:  # pragma: no cover - interface
        raise NotImplementedError


async def gather_limited(coros, limit: int):
    """Run coroutines with a concurrency limit, return results (exceptions are returned, not raised)."""
    sem = asyncio.Semaphore(limit)

    async def _w(c):
        async with sem:
            return await c

    return await asyncio.gather(*(_w(c) for c in coros), return_exceptions=True)


def ordered() -> List[Type[Module]]:
    from . import modules  # noqa: F401  (import side effect: registration)
    return sorted(REGISTRY.values(), key=lambda m: (m.phase, m.name))
