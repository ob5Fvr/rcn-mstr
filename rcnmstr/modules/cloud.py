"""Cloud storage asset discovery: permute org keywords + collected refs, check S3/GCS/Azure/DO for exposure."""
from __future__ import annotations

import asyncio
import re
from typing import List, Optional, Set, Tuple

from ..base import Module, gather_limited
from ..http import fetch

BUCKET_AFFIXES = ["", "-dev", "-staging", "-stg", "-prod", "-production", "-test", "-qa", "-uat", "-backup",
                  "-backups", "-bak", "-data", "-assets", "-static", "-media", "-images", "-img", "-uploads",
                  "-files", "-public", "-private", "-internal", "-logs", "-log", "-archive", "-cdn", "-web",
                  "-www", "-app", "-api", "-storage", "-store", "-config", "-secret", "-secrets", "-tmp",
                  "-reports", "-export", "-dumps", "-db", "-database", "-build", "-artifacts", "-releases",
                  "-downloads", "-content", "-user", "-users", "-customer", "-billing", "-invoices"]
PREFIXES = ["", "dev-", "staging-", "prod-", "test-", "backup-", "assets-", "static-", "media-", "cdn-",
            "files-", "data-", "app-", "api-", "internal-", "s3-", "storage-"]
BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")


def candidate_names(keywords: List[str]) -> List[str]:
    out: Set[str] = set()
    for kw in keywords:
        kw = kw.lower()
        for pre in PREFIXES:
            for suf in BUCKET_AFFIXES:
                name = f"{pre}{kw}{suf}"
                if BUCKET_NAME_RE.match(name) and ".." not in name:
                    out.add(name)
        # combined keywords
        for other in keywords:
            if other != kw:
                out.add(f"{kw}-{other}")
                out.add(f"{kw}{other}")
    return sorted(out)


def parse_ref(ref: str) -> Optional[Tuple[str, str]]:
    """Return (provider, bucket) from a reference string found in JS/HTML/CNAME."""
    ref = ref.lower().lstrip("https://").lstrip("http://")
    m = re.match(r"([a-z0-9.\-_]+)\.s3[.\-]", ref) or re.match(r"s3[.\-][a-z0-9.\-]*/([a-z0-9.\-_]+)", ref)
    if m:
        return ("s3", m.group(1))
    m = re.match(r"([a-z0-9.\-_]+)\.storage\.googleapis\.com", ref) or \
        re.match(r"storage\.googleapis\.com/([a-z0-9.\-_]+)", ref)
    if m:
        return ("gcs", m.group(1))
    m = re.match(r"([a-z0-9\-]+)\.blob\.core\.windows\.net", ref)
    if m:
        return ("azure", m.group(1))
    m = re.match(r"([a-z0-9.\-_]+)\.([a-z0-9]+)\.digitaloceanspaces\.com", ref)
    if m:
        return ("dospaces", m.group(1))
    return None


class CloudAssets(Module):
    name = "cloud"
    phase = 75
    mode = "normal"
    final = True
    description = "Discover & test S3/GCS/Azure/DigitalOcean buckets from org keywords and collected references"

    async def run(self, ctx):
        names: Set[str] = set(candidate_names(ctx.scope.keywords()))
        refs: Set[Tuple[str, str]] = set()
        for ref in ctx.cloud_refs:
            pr = parse_ref(ref)
            if pr:
                refs.add(pr)
                names.add(pr[1])
        # bucket-like CNAME targets
        for h, rec in ctx.hosts.items():
            for c in (rec.get("dns") or {}).get("cname", []):
                pr = parse_ref(c)
                if pr:
                    refs.add(pr)
        names = set(sorted(names)[: ctx.cfg.max_buckets])
        jobs = []
        for n in names:
            jobs.append(self._s3(ctx, n, explicit=(("s3", n) in refs)))
            jobs.append(self._gcs(ctx, n, explicit=(("gcs", n) in refs)))
            jobs.append(self._azure(ctx, n, explicit=(("azure", n) in refs)))
        for provider, bucket in refs:
            if provider == "dospaces":
                jobs.append(self._generic(ctx, f"https://{bucket}.nyc3.digitaloceanspaces.com/",
                                          "DigitalOcean Spaces", bucket, explicit=True))
        self.log.info("cloud: testing %d candidate bucket names", len(names))
        await gather_limited(jobs, ctx.cfg.concurrency)

    def _report(self, ctx, provider, bucket, url, state, evidence, explicit):
        if state == "public_listing":
            ctx.finding("cloud_bucket", "high", "high", url, f"Public {provider} bucket lists contents: {bucket}",
                        evidence, self.name, ["cloud", "bucket", "exposure"], dedupe_key=url,
                        next_steps=["Enumerate and download objects; check for sensitive data"])
        elif state == "exists_private":
            sev = "info" if not explicit else "low"
            ctx.finding("cloud_bucket", sev, "high", url, f"{provider} bucket exists (access denied): {bucket}",
                        evidence, self.name, ["cloud", "bucket"], dedupe_key=url,
                        next_steps=["Test write/ACL perms, pre-signed URL abuse"])
        elif state == "takeover" and explicit:
            ctx.finding("cloud_bucket", "high", "high", url,
                        f"Referenced {provider} bucket does not exist (claimable): {bucket}",
                        evidence, self.name, ["cloud", "bucket", "takeover"], dedupe_key=url,
                        next_steps=[f"Register bucket '{bucket}' to hijack referenced content"])

    async def _s3(self, ctx, bucket, explicit=False):
        if not BUCKET_NAME_RE.match(bucket):
            return
        url = f"https://{bucket}.s3.amazonaws.com/"
        r = await fetch(ctx.probe, url, timeout=ctx.cfg.timeout, max_bytes=200000, allow_redirects=True)
        if not r:
            return
        body = r.text
        if r.status == 200 and "<ListBucketResult" in body:
            keys = re.findall(r"<Key>([^<]+)</Key>", body)
            self._report(ctx, "S3", bucket, url, "public_listing",
                         {"objects_sample": keys[:40], "count_hint": len(keys)}, explicit)
        elif r.status == 403 or "AccessDenied" in body:
            self._report(ctx, "S3", bucket, url, "exists_private", {"status": r.status}, explicit)
        elif r.status == 404 and "NoSuchBucket" in body and explicit:
            self._report(ctx, "S3", bucket, url, "takeover", {"status": 404}, explicit)

    async def _gcs(self, ctx, bucket, explicit=False):
        url = f"https://storage.googleapis.com/{bucket}/"
        r = await fetch(ctx.probe, url, timeout=ctx.cfg.timeout, max_bytes=200000, allow_redirects=True)
        if not r:
            return
        body = r.text
        if r.status == 200 and ("<ListBucketResult" in body or "<Contents>" in body):
            keys = re.findall(r"<Key>([^<]+)</Key>", body)
            self._report(ctx, "GCS", bucket, url, "public_listing", {"objects_sample": keys[:40]}, explicit)
        elif r.status in (401, 403) or "AccessDenied" in body or "does not have storage" in body:
            self._report(ctx, "GCS", bucket, url, "exists_private", {"status": r.status}, explicit)

    async def _azure(self, ctx, bucket, explicit=False):
        # list containers via the blob service (works only if public); existence by DNS otherwise
        info = await ctx.resolver.resolve_host(f"{bucket}.blob.core.windows.net")
        if not info["resolved"]:
            if explicit:
                self._report(ctx, "Azure Blob", bucket, f"https://{bucket}.blob.core.windows.net/",
                             "takeover", {"dns": "NXDOMAIN"}, explicit)
            return
        url = f"https://{bucket}.blob.core.windows.net/?comp=list"
        r = await fetch(ctx.probe, url, timeout=ctx.cfg.timeout, max_bytes=200000)
        if r and r.status == 200 and "<EnumerationResults" in r.text:
            containers = re.findall(r"<Name>([^<]+)</Name>", r.text)
            self._report(ctx, "Azure Blob", bucket, url, "public_listing", {"containers": containers[:40]}, explicit)
        elif r and r.status in (403, 409):
            self._report(ctx, "Azure Blob", bucket, f"https://{bucket}.blob.core.windows.net/",
                         "exists_private", {"status": r.status}, explicit)

    async def _generic(self, ctx, url, provider, bucket, explicit=False):
        r = await fetch(ctx.probe, url, timeout=ctx.cfg.timeout, max_bytes=200000)
        if not r:
            return
        if r.status == 200 and "<ListBucketResult" in r.text:
            self._report(ctx, provider, bucket, url, "public_listing", {"status": 200}, explicit)
        elif r.status == 403:
            self._report(ctx, provider, bucket, url, "exists_private", {"status": 403}, explicit)
