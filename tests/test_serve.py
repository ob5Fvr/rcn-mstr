"""Read-only HTTP JSON API over a run dir."""
import pytest
from aiohttp.test_utils import TestClient, TestServer

from rcnmstr.serve import build_app
from rcnmstr.store import ReconStore


@pytest.fixture
def run_dir(selftest_run):
    return selftest_run


@pytest.fixture
async def client(run_dir):
    app = build_app(ReconStore.load(run_dir))
    async with TestClient(TestServer(app)) as c:
        yield c


@pytest.mark.asyncio
async def test_index(client):
    r = await client.get("/")
    assert r.status == 200
    j = await r.json()
    assert "endpoints" in j and j["summary"]["counts"]["hosts_total"] >= 4


@pytest.mark.asyncio
async def test_hypotheses_and_agent_plan(client):
    r = await client.get("/hypotheses")
    assert r.status == 200 and isinstance(await r.json(), list)
    r2 = await client.get("/agent-plan?top=3")
    plan = await r2.json()
    assert len(plan) <= 3 and all("agent_prompt" in p for p in plan)


@pytest.mark.asyncio
async def test_findings_filter(client):
    r = await client.get("/findings?min_severity=high")
    for f in await r.json():
        assert f["severity"] in ("high", "critical")


@pytest.mark.asyncio
async def test_finding_subgraph(client):
    allf = await (await client.get("/findings")).json()
    fid = allf[0]["id"]
    r = await client.get(f"/findings/{fid}")
    j = await r.json()
    assert j["finding"]["id"] == fid and "subgraph" in j
    r2 = await client.get("/findings/deadbeef")
    assert r2.status == 404


@pytest.mark.asyncio
async def test_query_endpoint(client):
    r = await client.get("/query", params={"q": "select hosts where resolved is True"})
    assert r.status == 200 and all(h["resolved"] for h in await r.json())
    bad = await client.get("/query", params={"q": "drop table"})
    assert bad.status == 400


@pytest.mark.asyncio
async def test_graph_node(client):
    hosts = await (await client.get("/hosts")).json()
    name = hosts[0]["host"]
    r = await client.get(f"/graph/node/host:{name}")
    assert r.status == 200
    j = await r.json()
    assert j["node"]["type"] == "host"
