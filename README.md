# rcn-mstr

**A modular, asynchronous recon framework that doesn't just list assets — it reasons about them.**

`rcn-mstr` ingests one or more root domains and produces raw, structured, machine-ingestible
reconnaissance data for bug-bounty and authorized security testing. Where other tools stop at
flat lists (subdomains, URLs, findings), rcn-mstr goes two steps further:

1. It builds a **correlation knowledge graph** linking every host, IP, ASN, certificate, favicon,
   technology and finding it observes.
2. On top of that graph it runs an **attack-hypothesis engine** that emits *ranked, evidence-linked
   attack chains* — each with a rationale, concrete reproduction steps, and a self-contained
   `agent_prompt` written for a downstream AI agent to execute.

The output is designed to be handed straight to an AI harness: start at `hypotheses.jsonl`, pivot
through the graph, drill into `findings.jsonl` for raw evidence.

> Single hard dependency: **aiohttp**. Everything else — the full DNS stack, TLS parsing, murmur3
> favicon hashing, simhash, permutation engine — is implemented from scratch with no third-party
> libraries. External binaries (subfinder, amass) are used *only* if present on `PATH`, never required.

---

## Why it's different

| Capability | Typical recon tools | rcn-mstr |
|---|---|---|
| Subdomain enumeration (passive + brute + permute) | ✅ | ✅ (15 passive sources, corpus-aware permutations) |
| Own DNS stack (no dnspython), sinkhole/hijack detection, DoH fallback | ✖ | ✅ |
| Feedback loop (TLS SAN / JS / CSP / archive → re-resolve → re-probe) | rare | ✅ core design |
| Takeover (CNAME + NS/lame-delegation + cloud) with confidence | partial | ✅ |
| Origin-IP discovery behind CDN (verified by Host-header + simhash) | rare | ✅ |
| WAF fingerprint **and bypass assessment** | ✖ | ✅ |
| **Correlation knowledge graph** | ✖ | ✅ |
| **Attack-hypothesis engine with agent prompts** | ✖ | ✅ |
| **Attack-surface drift between runs** | ✖ | ✅ |
| Interactive offline HTML report | ✖ | ✅ |
| AI-ingestible raw output (JSONL + index) | ✖ | ✅ by design |

---

## Install

```bash
pip install -e .          # from a clone
# or just run in place:
pip install aiohttp cryptography
python -m rcnmstr --help
```

Python 3.9+. `cryptography` is optional (richer TLS certificate parsing; falls back gracefully).

## Quickstart

```bash
# passive-only (no active traffic to the target)
rcn-mstr example.com --mode passive

# normal (default): passive + DNS + probe + content + JS + archives + cloud + correlate
rcn-mstr example.com

# deep: adds port scanning, origin-IP discovery, wider permutations
rcn-mstr example.com --mode deep -o out/example

# multiple roots + scope file
rcn-mstr acme.com acme.net --scope scope.txt --exclude out-of-scope.txt

# no egress? prove the whole pipeline works against a built-in mock internet:
rcn-mstr --self-test

# continuous recon: diff two runs
rcn-mstr --diff out/run-monday out/run-tuesday

# (re)build the interactive report
rcn-mstr --html out/example
```

Results land in `rcn-out/<domain>-<timestamp>/` (or `-o`). **Start at `index.json`.**

## Modes

- `passive` — third-party data only; no packets to the target (CT logs, passive DNS, archives).
- `normal` — active DNS, HTTP probing, content discovery, JS analysis, archives, cloud, correlation.
- `deep` — adds TCP port scanning + banner grabbing, origin-IP discovery, wider ASN sweeps.

## Modules

Run `rcn-mstr --list-modules` for the live list. Each is a self-registering class with a
`phase`, a minimum `mode`, and an `async run(ctx)`; enable/disable with `--modules` / `--skip`.

| phase | module | what it does |
|---|---|---|
| 10 | `passive` | crt.sh, certspotter, hackertarget, OTX, urlscan, anubis, rapiddns, subdomain.center, columbus + key-gated (VT, SecurityTrails, Chaos, Shodan, FullHunt, GitHub) |
| 20 | `resolve` | own-stack A/AAAA/CNAME resolution, wildcard tagging |
| 22 | `dnsrecords` | apex MX/NS/TXT/SOA/CAA/SRV, SaaS verification tokens, SPF/DMARC/DKIM analysis, AXFR |
| 25 | `brute` | ~1,400-word embedded brute force with wildcard filtering |
| 26 | `permute` | corpus-aware dnsgen/altdns-style permutations |
| 30 | `takeover` | dangling CNAME, service fingerprints, NS/lame-delegation, cloud buckets, with confidence |
| 40 | `netintel` | Team-Cymru ASN/prefix, CDN/WAF classification (ASN + CIDR + headers), PTR, Shodan InternetDB, RDAP |
| 41 | `ripestat` | announced prefixes for org-owned ASNs |
| 45 | `portscan` | (deep) async TCP connect scan + unauthenticated banner grab |
| 50 | `probe` | HTTP(S): status, title, tech (~80 sigs), favicon mmh3, TLS cert, security headers, CORS |
| 55 | `origin` | origin-IP discovery behind CDNs, verified by Host-header + body simhash |
| 58 | `waf` | WAF/edge fingerprinting + documented bypass assessment on blocked endpoints |
| 60 | `content` | ~90 sensitive paths, each verified by content signature, with soft-404 calibration |
| 65 | `js` | crawl + JS/source-map analysis: endpoints, hosts, cloud refs, internal IPs, ~55 secret regexes |
| 70 | `archives` | wayback/CommonCrawl/OTX/urlscan URL harvest, uro-dedupe, gf-classify |
| 75 | `cloud` | S3/GCS/Azure/DO bucket discovery + exposure testing |
| 90 | `analysis` | correlate signals into prioritised findings + attack-surface summary |
| 95 | `correlate` | **knowledge graph + attack-hypothesis engine** |

## Output layout

```
index.json          machine entrypoint: summary, graph stats, top hypotheses, file map
hypotheses.jsonl    ranked attack chains (rationale, evidence, steps, agent_prompt) — START HERE
findings.jsonl      ranked findings (id,type,severity,confidence,target,title,evidence,next_steps)
graph_nodes.jsonl   typed graph nodes (host/ip/asn/cert/favicon/tech/service/finding)
graph_edges.jsonl   typed edges (resolves_to/in_asn/presents_cert/covers/serves/runs/about/cname)
graph.dot           Graphviz rendering of the graph
clusters.json       cert/favicon/body/co-host/ASN clusters
hosts.jsonl/.txt    every host with DNS + HTTP context; hosts_live.txt, hosts_resolved.txt
ips.jsonl           IPs with ASN/CDN/PTR/InternetDB/ports/banners
services.jsonl      HTTP services (status,title,tech,tls,headers,favicon,cors,content)
zones.jsonl         apex records + SPF/DMARC/DKIM analysis
urls_all.txt        deduped archive+crawl URL surface; urls_live.txt; params.txt; paths.txt
report.html         self-contained interactive report
run.json            run metadata, per-source + per-module status
```

Every record is raw JSON. See [docs/OUTPUT.md](docs/OUTPUT.md) for the full schema.

## API keys (optional, all free-tier)

Keys unlock extra passive sources. Supply via env vars or `-k keys.txt` (`KEY=value` or JSON):

```
VIRUSTOTAL_KEY=...      SECURITYTRAILS_KEY=...   CHAOS_KEY=...
SHODAN_KEY=...          FULLHUNT_KEY=...         GITHUB_TOKEN=...
URLSCAN_KEY=...         CERTSPOTTER_KEY=...      OTX_KEY=...
```

rcn-mstr is fully functional with **zero keys** — the keyless sources alone are comprehensive.

## AI-harness integration

The output is built to be consumed by a downstream AI agent. Three ways in:

```bash
# 1. ranked attack plan: each item has a self-contained agent_prompt
rcn-mstr --agent-plan rcn-out/example-...

# 2. query the run with a tiny DSL
rcn-mstr --query rcn-out/example-... "select findings where severity is high"
rcn-mstr --query rcn-out/example-... "select hosts where cdn is null and resolved is True"

# 3. live read-only JSON API (localhost) for an agent to call
rcn-mstr --serve rcn-out/example-...      # GET /hypotheses /findings /graph/node/{id} /query?q=...
```

Or from Python:

```python
from rcnmstr.store import ReconStore
s = ReconStore.load("rcn-out/example-...")
for h in s.agent_plan(top=10):
    run_agent(h["agent_prompt"], targets=h["targets"])   # feed the chain to your agent
s.subgraph_for_finding(fid)         # evidence subgraph for any finding
s.neighbors("host:api.example.com") # traverse the correlation graph
```

A typical loop: `rcn-mstr target.com` → read `hypotheses.jsonl` → dispatch each `agent_prompt` to an
autonomous agent → on the next scheduled run, `rcn-mstr --diff old new` surfaces only what changed.

## Architecture

```
       ┌────────── passive sources ──────────┐
roots ─┤ CT logs, passive DNS, search, archives │──► hosts
       └───────────────────────────────────────┘      │
                                                       ▼
                       ┌──────── feedback loop (--max-rounds) ────────┐
                       │  resolve → dnsrecords → brute → permute       │
                       │  → takeover → netintel → probe → waf          │
                       │  new hosts from TLS SANs / JS / CSP / archive │
                       │  / PTR / InternetDB are fed back in           │
                       └───────────────────────────────────────────────┘
                                                       │ (fixpoint)
                                                       ▼
          final: origin · content · js · archives · cloud · analysis · correlate
                                                       │
                                                       ▼
                 index.json · hypotheses.jsonl · graph · findings · report.html
```

The DNS stack (`rcnmstr/dns/`) is a from-scratch stub resolver: EDNS0 query builder, compression-safe
parser, one UDP socket per upstream multiplexed by transaction id with question-matching anti-spoofing,
TCP fallback on truncation, retry/rotate across 16 resolvers, a health check that detects
sinkholing/hijacking (a real name must resolve **and** a random name must be NXDOMAIN), and automatic
DNS-over-HTTPS fallback. If DNS is unusable it **aborts loudly** rather than emit all-NXDOMAIN garbage.

## Extending

Drop a class in `rcnmstr/modules/`; it auto-registers:

```python
from ..base import Module

class MyModule(Module):
    name = "mymod"
    phase = 52          # ordering
    mode = "normal"     # passive | normal | deep
    loop = False        # re-run each feedback round?
    final = False       # run after the loop converges?

    async def run(self, ctx):
        for host in ctx.live_hosts():
            ...
        ctx.finding("my_type", "medium", "high", host, "Title", evidence={...}, module=self.name)
        ctx.add_host("new.example.com", self.name)   # feeds the loop
```

See [docs/MODULES.md](docs/MODULES.md).

## Testing

```bash
pip install pytest pytest-asyncio cryptography
pytest -q           # 230+ tests: wire codec, resolver, every module, 40 randomized
                    # end-to-end scenarios, property sweeps, performance benchmarks
```

Tests run entirely against in-process fake DNS/HTTP servers — no network required.

## Legal

For authorized security testing only: bug-bounty programs within scope, systems you own, or
engagements with explicit written permission. The WAF-bypass and content-discovery modules send
crafted-but-read-only requests; use them only where you are permitted to. You are responsible for
staying within scope and law.

## License

MIT
