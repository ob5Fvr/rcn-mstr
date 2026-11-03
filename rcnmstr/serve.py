"""Read-only HTTP JSON API over a finished run, for a downstream AI harness to query live.

    rcn-mstr --serve rcn-out/example-...   # binds 127.0.0.1:8777 by default

Endpoints (all JSON):
    GET /                      -> index.json + endpoint map
    GET /summary               -> run summary
    GET /hypotheses            -> ranked attack chains (?category=&min_confidence=)
    GET /agent-plan            -> top agent plan (?top=)
    GET /findings              -> findings (?severity=&type=&min_severity=&tag=)
    GET /findings/{id}         -> one finding + its evidence subgraph
    GET /hosts                 -> hosts (?live=&cdn=&resolved=)
    GET /hosts/{name}          -> one host
    GET /ips/{addr}            -> one ip
    GET /services              -> services (?status=)
    GET /graph/node/{id}       -> node + out/in neighbors
    GET /query?q=...           -> store query DSL

Bind is localhost-only by design. It never writes.
"""
from __future__ import annotations

from .store import ReconStore


def build_app(store: ReconStore):
    from aiohttp import web

    def J(data, status=200):
        return web.json_response(data, status=status, dumps=_dumps)

    async def index(req):
        return J({"schema": store.index.get("schema"), "summary": store.summary,
                  "graph": store.index.get("graph", {}),
                  "endpoints": ["/summary", "/hypotheses", "/agent-plan", "/findings", "/findings/{id}",
                                "/hosts", "/hosts/{name}", "/ips/{addr}", "/services",
                                "/graph/node/{id}", "/query?q="]})

    async def summary(req):
        return J(store.summary)

    async def hypotheses(req):
        cat = req.query.get("category")
        mc = float(req.query.get("min_confidence", 0) or 0)
        return J(store.hypotheses(category=cat, min_confidence=mc))

    async def agent_plan(req):
        return J(store.agent_plan(top=int(req.query.get("top", 10))))

    async def findings(req):
        return J(store.findings(severity=req.query.get("severity"), type=req.query.get("type"),
                                min_severity=req.query.get("min_severity"), tag=req.query.get("tag")))

    async def finding_one(req):
        fid = req.match_info["id"]
        f = store.finding(fid)
        if not f:
            return J({"error": "not found"}, 404)
        return J({"finding": f, "subgraph": store.subgraph_for_finding(fid, depth=2)})

    async def hosts(req):
        def b(x):
            return {"true": True, "false": False}.get(str(req.query.get(x, "")).lower())
        return J(store.hosts(live=b("live"), cdn=b("cdn"), resolved=b("resolved")))

    async def host_one(req):
        h = store.host(req.match_info["name"])
        return J(h or {"error": "not found"}, 200 if h else 404)

    async def ip_one(req):
        i = store.ip(req.match_info["addr"])
        return J(i or {"error": "not found"}, 200 if i else 404)

    async def services(req):
        st = req.query.get("status")
        return J(store.services(status=int(st) if st else None))

    async def node(req):
        nid = req.match_info["id"]
        n = store.node(nid)
        if not n:
            return J({"error": "not found"}, 404)
        return J({"node": n, "out": store.neighbors(nid, direction="out"),
                  "in": store.neighbors(nid, direction="in")})

    async def query(req):
        q = req.query.get("q", "")
        try:
            return J(store.query(q))
        except ValueError as e:
            return J({"error": str(e)}, 400)

    app = web.Application()
    app.add_routes([
        web.get("/", index), web.get("/summary", summary), web.get("/hypotheses", hypotheses),
        web.get("/agent-plan", agent_plan), web.get("/findings", findings),
        web.get("/findings/{id}", finding_one), web.get("/hosts", hosts),
        web.get("/hosts/{name}", host_one), web.get("/ips/{addr}", ip_one),
        web.get("/services", services), web.get("/graph/node/{id}", node), web.get("/query", query),
    ])
    return app


def _dumps(obj):
    import json
    return json.dumps(obj, default=str)


def serve(outdir: str, host: str = "127.0.0.1", port: int = 8777):
    from aiohttp import web
    store = ReconStore.load(outdir)
    app = build_app(store)
    print(f"rcn-mstr serving {outdir} at http://{host}:{port}  (Ctrl-C to stop)")
    web.run_app(app, host=host, port=port, print=None)
