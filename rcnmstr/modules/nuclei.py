"""Optional nuclei passthrough: run ProjectDiscovery's nuclei against live URLs and ingest results.

Only runs in deep mode with --nuclei and only if `nuclei` is on PATH. Never required. Each nuclei
result becomes a rcn-mstr finding, mapped by its severity, so it flows into the graph and hypotheses.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile

from ..base import Module

SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
           "info": "info", "unknown": "info"}


class Nuclei(Module):
    name = "nuclei"
    phase = 80
    mode = "deep"
    final = True
    default = True
    description = "Run nuclei against live URLs if present (deep + --nuclei); ingest results as findings"

    async def run(self, ctx):
        if not ctx.cfg.nuclei:
            return
        binary = shutil.which("nuclei")
        if not binary:
            self.log.info("nuclei not on PATH; skipping")
            ctx.module_status.setdefault(self.name, {}).setdefault("errors", []).append("nuclei not on PATH")
            return
        urls = sorted({s["url"] for s in ctx.services.values() if s["status"] < 500})
        if not urls:
            return
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(urls))
            infile = fh.name
        cmd = [binary, "-silent", "-jsonl", "-l", infile, "-rl", "150", "-c", "25",
               "-timeout", str(int(ctx.cfg.timeout))]
        self.log.info("running nuclei on %d urls", len(urls))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(proc.communicate(), ctx.cfg.module_timeout)
        except (asyncio.TimeoutError, OSError) as e:
            self.log.warning("nuclei run failed: %s", e)
            return
        count = 0
        for line in out.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            count += self._ingest(ctx, r)
        self.log.info("nuclei: %d findings ingested", count)
        ctx.stats["nuclei_findings"] = count

    def _ingest(self, ctx, r) -> int:
        info = r.get("info", {})
        sev = SEV_MAP.get((info.get("severity") or "info").lower(), "info")
        target = r.get("matched-at") or r.get("host") or r.get("url") or ""
        tid = r.get("template-id", "nuclei")
        ctx.emit("nuclei", r)
        ctx.finding("nuclei", sev, "high", target, f"[nuclei:{tid}] {info.get('name', tid)}",
                    {"template": tid, "matcher": r.get("matcher-name"), "type": r.get("type"),
                     "matched_at": target, "tags": info.get("tags"),
                     "reference": info.get("reference"), "curl": r.get("curl-command")},
                    self.name, ["nuclei"] + (info.get("tags") or [])[:6], dedupe_key=f"{tid}|{target}")
        return 1
