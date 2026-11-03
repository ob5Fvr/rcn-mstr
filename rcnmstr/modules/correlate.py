"""Final correlation stage: build the knowledge graph, derive clusters, emit attack hypotheses."""
from __future__ import annotations

from .. import graph as G
from .. import hypotheses as HYP
from ..base import Module


class Correlate(Module):
    name = "correlate"
    phase = 95  # after analysis (90)
    mode = "passive"
    final = True
    description = "Build the correlation knowledge graph + attack-hypothesis engine (the differentiator)"

    async def run(self, ctx):
        g = G.build_graph(ctx)
        clusters = G.all_clusters(ctx, g)
        ctx.graph = g
        ctx.clusters = clusters

        # emit graph artifacts
        nodes, edges = g.to_jsonl()
        ctx.write_jsonl("graph_nodes.jsonl", nodes)
        ctx.write_jsonl("graph_edges.jsonl", edges)
        try:
            with open(f"{ctx.outdir}/graph.dot", "w", encoding="utf-8") as fh:
                fh.write(g.to_dot())
        except Exception:  # noqa
            pass
        ctx.write_json("clusters.json", clusters)
        ctx.stats["graph"] = g.stats()

        # cluster-level findings (structure a flat list can't show)
        for cl in clusters["cert"]:
            if len(cl["hosts"]) >= 2:
                ctx.finding("asset_cluster", "info", "medium", cl["cn"] or cl["cert"][:16],
                            f"{len(cl['hosts'])} hosts share one TLS certificate",
                            {"hosts": cl["hosts"], "sans": cl.get("sans", [])[:30]}, self.name,
                            ["cluster", "cert"], dedupe_key="cert:" + cl["cert"])
        for cl in clusters["cohosted_ip"]:
            ctx.finding("asset_cluster", "info", "high", cl["ip"],
                        f"{len(cl['hosts'])} in-scope hosts co-hosted on {cl['ip']} (vhost pivot)",
                        {"hosts": cl["hosts"][:50], "asn": cl.get("asn"), "as_name": cl.get("as_name")},
                        self.name, ["cluster", "cohost", "vhost"], dedupe_key="cohost:" + cl["ip"])
        for cl in clusters["favicon"]:
            if len(cl["services"]) >= 3:
                ctx.finding("asset_cluster", "info", "low", cl["favicon_mmh3"],
                            f"{len(cl['services'])} services share favicon {cl['favicon_mmh3']} (same app family)",
                            {"services": cl["services"][:40]}, self.name, ["cluster", "favicon"],
                            dedupe_key="fav:" + cl["favicon_mmh3"])

        # attack hypotheses
        hyps = HYP.generate(ctx, g, clusters)
        ctx.hypotheses = hyps
        ctx.write_jsonl("hypotheses.jsonl", hyps)
        ctx.stats["hypotheses"] = len(hyps)
        self.log.info("correlation: graph %s, %d clusters, %d attack hypotheses",
                      g.stats(), sum(len(v) for v in clusters.values()), len(hyps))
        if hyps:
            top = hyps[0]
            self.log.info("top hypothesis: [%s] %s", top["severity"].upper(), top["title"])
