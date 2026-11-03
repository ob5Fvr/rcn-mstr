# Changelog

## 1.0.0

Initial release of rcn-mstr — a modular async recon framework with AI-ingestible output.

### Core
- From-scratch DNS stack (no dnspython): EDNS0 builder, compression-safe parser for
  A/AAAA/CNAME/NS/MX/TXT/SOA/PTR/SRV/CAA/NSEC/NSEC3, UDP multiplexing with question-match
  anti-spoofing, TCP fallback, 16-resolver rotation, sinkhole/hijack health check, DoH fallback,
  AXFR, PTR, direct authoritative queries.
- Async pipeline with a discovery feedback loop (new hosts from TLS SANs / JS / CSP / archives /
  PTR / InternetDB are re-resolved and re-probed until fixpoint).
- Single hard dependency: aiohttp. Custom aiohttp resolver backed by the internal DNS cache.
- Per-host rate limiting / politeness.

### Modules (20)
passive, resolve, dnsrecords, brute, permute, takeover, netintel, ripestat, portscan, probe,
origin, waf, content, js, archives, cloud, related, nuclei, analysis, correlate.

### Differentiators
- **Correlation knowledge graph** (hosts/IPs/ASNs/certs/favicons/tech/services/findings + typed edges).
- **Attack-hypothesis engine**: ranked, evidence-linked attack chains with reproduction steps and a
  self-contained `agent_prompt` for a downstream AI agent.
- **Attack-surface drift** (`--diff`) for continuous recon.
- **ReconStore** query API + CLI (`--query`, `--agent-plan`) for programmatic/AI ingestion.
- Self-contained **interactive HTML report** (`--html`).
- NSEC/NSEC3 DNSSEC zone-walking enumeration.
- WAF fingerprinting + documented bypass assessment.
- Origin-IP discovery behind CDNs (Host-header + body-simhash verified).
- Favicon product fingerprinting (populatable DB).
- Related-domain / acquisition discovery via shared TLS certificates (+ optional scope expansion).

### Ops
- `--self-test` runs the whole pipeline against an in-process mock internet (no egress).
- Config-file support (`--config`), `--fail-on <severity>` CI gate, exit 10 on drift.
- 270+ tests (unit, integration, randomized end-to-end scenarios, property sweeps, performance).
