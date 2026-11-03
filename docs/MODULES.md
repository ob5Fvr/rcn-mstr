# Writing rcn-mstr modules

A module is a self-registering class. Dropping a subclass of `Module` anywhere imported by
`rcnmstr/modules/__init__.py` registers it automatically (via `__init_subclass__`).

## Anatomy

```python
from ..base import Module, gather_limited

class Example(Module):
    name = "example"       # unique; used by --modules/--skip and as the event-stream label
    phase = 52             # execution order (lower first). See the phase map below.
    mode = "normal"        # minimum run mode: "passive" | "normal" | "deep"
    loop = False           # True => re-run every feedback round (not just round 1)
    final = False          # True => run once after the feedback loop converges
    default = True         # False => only runs when explicitly named in --modules
    description = "one line shown by --list-modules"

    async def run(self, ctx):
        ...
```

Exactly one of the loop/final behaviours applies:
- `loop=True`  — runs in every round of the discovery feedback loop (resolve, probe, takeover, ...).
- `final=True` — runs once after the loop reaches a fixpoint (content, js, cloud, correlate, ...).
- neither      — runs only in round 1.

## Phase map (convention)

```
10 passive     20 resolve     22 dnsrecords   25 brute      26 permute
30 takeover    40 netintel    41 ripestat     45 portscan   50 probe
55 origin      58 waf         60 content      65 js         70 archives
75 cloud       90 analysis    95 correlate
```

Pick a phase near modules you depend on (e.g. anything consuming HTTP services uses phase > 50).

## The Context object (`ctx`)

Shared state + output. Key members:

| member | purpose |
|---|---|
| `ctx.cfg` | the `Config` (mode, concurrency, timeouts, keys, flags) |
| `ctx.scope` | `Scope` — `in_scope(h)`, `root_of(h)`, `extract_hosts(text)`, `keywords()` |
| `ctx.resolver` | the async DNS resolver — `query`, `resolve_host`, `ptr`, `axfr`, `query_server` |
| `ctx.probe` | aiohttp session for target traffic (own DNS cache, TLS verify off) |
| `ctx.api` | aiohttp session for third-party APIs (system CA, honours proxies) |
| `ctx.hosts` | dict host → record (dns, http, cdn, tags, sources) |
| `ctx.ips` / `ctx.services` / `ctx.zones` | per-entity tables |
| `ctx.round` | current feedback round |

### Adding data

```python
ctx.add_host("new.example.com", source=self.name)   # scope-checked; feeds the loop if new
ctx.add_hosts(iterable, self.name)
ctx.tag_host(host, "interesting")
ctx.ip_rec(ip)["ports"].append(8080)
ctx.web_targets.add((host, 8080, "http"))            # extra probe target
ctx.paths.add("/api/v2")                             # feeds content discovery wordlist
ctx.cloud_refs.add("bucket.s3.amazonaws.com")        # feeds the cloud module
```

### Emitting results

```python
ctx.finding(type, severity, confidence, target, title,
            evidence={...}, module=self.name, tags=(...), next_steps=[...], dedupe_key=None)
# severity:   info | low | medium | high | critical
# confidence: tentative | low | medium | high | confirmed

ctx.emit("my_stream", {...})       # append a record to my_stream.jsonl (raw event log)
```

Findings dedupe on `(type, target, dedupe_key or title)`, upgrading severity/confidence on repeats.

## Concurrency

Use `gather_limited(coros, limit)` from `base` to bound fan-out. HTTP concurrency should respect
`ctx.cfg.concurrency`; DNS uses `ctx.cfg.dns_concurrency`. Always set per-request timeouts.

## Feeding the feedback loop

The loop re-runs `loop=True` modules while new hosts keep appearing. Any `ctx.add_host` of a new
in-scope name (from a TLS SAN, a JS reference, a CSP directive, an archived URL, a PTR record, ...)
triggers another round of resolve → probe. This is the core of rcn-mstr's coverage; emit hosts
liberally (they are scope-checked and wildcard-filtered automatically).

## Testing a module

Use the fixtures in `tests/conftest.py` (`fake_dns`, `fake_http`) and drive the real engine with
`modules=[...]`. See `tests/test_integration.py` and `tests/test_networked_modules.py`.
