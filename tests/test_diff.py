"""Attack-surface drift / diff between two run directories."""
import json
import os

from rcnmstr.diff import diff_runs, summarize


def _write_run(d, hosts, live, ips=None, services=None, findings=None, hyps=None):
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "hosts.txt"), "w").write("\n".join(hosts) + "\n")
    open(os.path.join(d, "hosts_live.txt"), "w").write("\n".join(live) + "\n")
    for name, recs in [("ips.jsonl", ips), ("services.jsonl", services),
                       ("findings.jsonl", findings), ("hypotheses.jsonl", hyps)]:
        with open(os.path.join(d, name), "w") as fh:
            for r in recs or []:
                fh.write(json.dumps(r) + "\n")


def test_diff_new_hosts(tmp_path):
    old = str(tmp_path / "old")
    new = str(tmp_path / "new")
    _write_run(old, ["a.example.com"], ["a.example.com"])
    _write_run(new, ["a.example.com", "b.example.com"], ["a.example.com", "b.example.com"])
    d = diff_runs(old, new)
    assert d["hosts"]["new"] == ["b.example.com"]
    assert "b.example.com" in d["hosts"]["newly_live"]
    assert d["has_changes"]
    assert d["drift_score"] > 0


def test_diff_port_changes(tmp_path):
    old = str(tmp_path / "o")
    new = str(tmp_path / "n")
    _write_run(old, ["a.example.com"], ["a.example.com"], ips=[{"ip": "1.1.1.1", "ports": [80], "hosts": ["a.example.com"]}])
    _write_run(new, ["a.example.com"], ["a.example.com"], ips=[{"ip": "1.1.1.1", "ports": [80, 22, 6379], "hosts": ["a.example.com"]}])
    d = diff_runs(old, new)
    pc = d["ips"]["port_changes"]
    assert pc and set(pc[0]["new_ports"]) == {22, 6379}


def test_diff_service_and_cert_change(tmp_path):
    old = str(tmp_path / "o")
    new = str(tmp_path / "n")
    _write_run(old, ["a.example.com"], ["a.example.com"], services=[
        {"url": "https://a.example.com", "status": 403, "tech": [{"name": "Nginx"}],
         "tls": {"fingerprint_sha256": "AAA"}, "title": "forbidden"}])
    _write_run(new, ["a.example.com"], ["a.example.com"], services=[
        {"url": "https://a.example.com", "status": 200, "tech": [{"name": "Nginx"}, {"name": "PHP"}],
         "tls": {"fingerprint_sha256": "BBB"}, "title": "home"}])
    d = diff_runs(old, new)
    ch = d["services"]["changed"][0]["changes"]
    assert ch["status"] == [403, 200]
    assert ch["tech_added"] == ["PHP"]
    assert ch["cert_changed"] == ["AAA", "BBB"]


def test_diff_findings(tmp_path):
    old = str(tmp_path / "o")
    new = str(tmp_path / "n")
    _write_run(old, ["a.example.com"], ["a.example.com"], findings=[
        {"id": "f1", "type": "x", "severity": "low", "target": "a", "title": "old"}])
    _write_run(new, ["a.example.com"], ["a.example.com"], findings=[
        {"id": "f2", "type": "subdomain_takeover", "severity": "high", "target": "b.example.com", "title": "takeover"}])
    d = diff_runs(old, new)
    assert d["findings"]["new"][0]["id"] == "f2"
    assert d["findings"]["resolved"][0]["id"] == "f1"
    assert d["drift_score"] >= 8  # high finding weighted


def test_diff_no_changes(tmp_path):
    old = str(tmp_path / "o")
    new = str(tmp_path / "n")
    _write_run(old, ["a.example.com"], ["a.example.com"])
    _write_run(new, ["a.example.com"], ["a.example.com"])
    d = diff_runs(old, new)
    assert not d["has_changes"]
    assert d["drift_score"] == 0


def test_summarize_renders(tmp_path):
    old = str(tmp_path / "o")
    new = str(tmp_path / "n")
    _write_run(old, ["a.example.com"], [])
    _write_run(new, ["a.example.com", "new.example.com"], ["new.example.com"],
               hyps=[{"id": "h1", "severity": "high", "title": "takeover ready"}])
    s = summarize(diff_runs(old, new))
    assert "drift" in s and "new.example.com" in s and "takeover ready" in s


def test_cli_diff(tmp_path, capsys):
    from rcnmstr.cli import main
    old = str(tmp_path / "o")
    new = str(tmp_path / "n")
    _write_run(old, ["a.example.com"], ["a.example.com"])
    _write_run(new, ["a.example.com", "b.example.com"], ["a.example.com", "b.example.com"])
    rc = main(["--diff", old, new])
    assert rc == 10  # changes detected
    assert "b.example.com" in capsys.readouterr().out
