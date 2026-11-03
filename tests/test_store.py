"""ReconStore query API, driven by a real self-test run."""
import pytest

from rcnmstr.store import ReconStore


@pytest.fixture(scope="module")
def run_dir(tmp_path_factory):
    import asyncio
    from rcnmstr.selftest import run_self_test
    d = str(tmp_path_factory.mktemp("run"))
    asyncio.run(run_self_test(d))
    return d


def test_load_and_counts(run_dir):
    s = ReconStore.load(run_dir)
    assert s.counts()["hosts_total"] >= 4
    assert len(s.hypotheses()) >= 1


def test_findings_filters(run_dir):
    s = ReconStore.load(run_dir)
    all_f = s.findings()
    highs = s.findings(min_severity="high")
    assert len(highs) <= len(all_f)
    for f in highs:
        assert f["severity"] in ("high", "critical")
    secrets = s.findings(type="secret")
    assert all(f["type"] == "secret" for f in secrets)


def test_agent_plan(run_dir):
    s = ReconStore.load(run_dir)
    plan = s.agent_plan(top=5)
    assert plan and all("agent_prompt" in p and p["agent_prompt"] for p in plan)


def test_graph_traversal(run_dir):
    s = ReconStore.load(run_dir)
    # find a host node and walk to its services/ips
    host_nodes = [nid for nid in s._nodes if nid.startswith("host:")]
    assert host_nodes
    nb = s.neighbors(host_nodes[0], direction="out")
    assert isinstance(nb, list)


def test_subgraph_for_finding(run_dir):
    s = ReconStore.load(run_dir)
    f = s.findings()[0]
    sg = s.subgraph_for_finding(f["id"], depth=1)
    assert any(n["id"] == f"finding:{f['id']}" for n in sg["nodes"])


def test_query_dsl(run_dir):
    s = ReconStore.load(run_dir)
    direct = s.query("select hosts where cdn is null")
    assert all(not h.get("cdn") for h in direct)
    resolved = s.query("select hosts where resolved is True")
    assert all(h["resolved"] for h in resolved)
    crit = s.query("select findings where severity is high")
    assert all(f["severity"] == "high" for f in crit)


def test_query_contains_and_numeric(run_dir):
    s = ReconStore.load(run_dir)
    # services with status >= 200
    svcs = s.query("select services where status >= 200")
    assert all(x["status"] >= 200 for x in svcs)


def test_query_errors(run_dir):
    s = ReconStore.load(run_dir)
    with pytest.raises(ValueError):
        s.query("delete everything")
    with pytest.raises(ValueError):
        s.query("select nonexistent")


def test_load_missing_dir():
    import pytest
    with pytest.raises(FileNotFoundError):
        ReconStore.load("/no/such/dir/xyz")
