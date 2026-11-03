"""Render a self-contained interactive HTML attack-surface report from a run directory.

No external dependencies: the graph is drawn with a tiny inline force-directed layout in vanilla JS/SVG,
so the file opens offline. Used by `rcn-mstr --html` and the self-test.
"""
from __future__ import annotations

import html
import json
import os


def _load_jsonl(path):
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def _load_json(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    return json.load(open(path, encoding="utf-8"))


SEV_COLOR = {"critical": "#b3123b", "high": "#e8590c", "medium": "#f59f00", "low": "#4c8", "info": "#5b7"}


def build_html(outdir: str) -> str:
    index = _load_json(os.path.join(outdir, "index.json"))
    summary = index.get("summary", {})
    counts = summary.get("counts", {})
    findings = _load_jsonl(os.path.join(outdir, "findings.jsonl"))
    hyps = _load_jsonl(os.path.join(outdir, "hypotheses.jsonl"))
    nodes = _load_jsonl(os.path.join(outdir, "graph_nodes.jsonl"))
    edges = _load_jsonl(os.path.join(outdir, "graph_edges.jsonl"))
    roots = ", ".join(summary.get("roots", []))

    # cap graph size for the browser
    if len(nodes) > 600:
        keep = {n["id"] for n in nodes[:600]}
        nodes = [n for n in nodes if n["id"] in keep]
        edges = [e for e in edges if e["src"] in keep and e["dst"] in keep]

    gdata = json.dumps({"nodes": [{"id": n["id"], "t": n["type"], "l": n["label"][:28]} for n in nodes],
                        "edges": [{"s": e["src"], "d": e["dst"], "t": e["type"]} for e in edges]})

    def esc(x):
        return html.escape(str(x)) if x is not None else ""

    sev_badges = "".join(
        f'<span class="pill" style="background:{SEV_COLOR.get(k, "#888")}">{k}: {v}</span>'
        for k, v in summary.get("findings_by_severity", {}).items())

    hyp_rows = []
    for h in hyps:
        ev = esc(json.dumps(h.get("evidence", {}))[:400])
        steps = "".join(f"<li>{esc(s)}</li>" for s in h.get("steps", []))
        hyp_rows.append(f"""
        <div class="card" data-sev="{esc(h['severity'])}">
          <div class="chead"><span class="pill" style="background:{SEV_COLOR.get(h['severity'], '#888')}">
            {esc(h['severity'])}</span> <span class="conf">conf {esc(h['confidence'])}</span>
            <b>{esc(h['title'])}</b> <span class="cat">{esc(h['category'])}</span></div>
          <div class="rat">{esc(h.get('rationale', ''))}</div>
          <div class="targets">targets: {esc(', '.join(h.get('targets', [])))}</div>
          <details><summary>steps &amp; agent prompt</summary>
            <ol>{steps}</ol>
            <div class="prompt"><b>agent_prompt:</b> {esc(h.get('agent_prompt', ''))}</div>
            <pre class="ev">{ev}</pre>
          </details>
        </div>""")

    find_rows = []
    for f in findings[:800]:
        find_rows.append(
            f'<tr data-sev="{esc(f["severity"])}"><td><span class="dot" '
            f'style="background:{SEV_COLOR.get(f["severity"], "#888")}"></span>{esc(f["severity"])}</td>'
            f'<td>{esc(f["confidence"])}</td><td>{esc(f["type"])}</td><td class="tgt">{esc(f["target"])}</td>'
            f'<td>{esc(f["title"])}</td></tr>')

    return _TEMPLATE.format(
        roots=esc(roots) or "recon", sev_badges=sev_badges,
        hosts_total=counts.get("hosts_total", 0), hosts_live=counts.get("hosts_live", 0),
        hosts_direct=counts.get("hosts_direct", 0), hosts_cdn=counts.get("hosts_cdn", 0),
        ips=counts.get("ips", 0), services=counts.get("services", 0),
        findings=counts.get("findings", 0), hyp_count=len(hyps),
        graph_nodes=index.get("graph", {}).get("nodes", len(nodes)),
        graph_edges=index.get("graph", {}).get("edges", len(edges)),
        hyp_rows="".join(hyp_rows) or "<p>No attack hypotheses generated.</p>",
        find_rows="".join(find_rows) or "<tr><td colspan=5>No findings.</td></tr>",
        gdata=gdata)


def write_html(outdir: str, filename: str = "report.html") -> str:
    path = os.path.join(outdir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_html(outdir))
    return path


_TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rcn-mstr: {roots}</title>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;--acc:#58a6ff}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
header{{padding:16px 20px;border-bottom:1px solid var(--line);background:var(--panel)}}
h1{{margin:0;font-size:18px}} h1 span{{color:var(--acc)}}
.sub{{color:var(--mut);font-size:12px;margin-top:4px}}
.stats{{display:flex;flex-wrap:wrap;gap:10px;padding:14px 20px}}
.stat{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 14px;min-width:88px}}
.stat b{{display:block;font-size:20px}} .stat span{{color:var(--mut);font-size:11px;text-transform:uppercase}}
.pill{{display:inline-block;color:#fff;border-radius:10px;padding:1px 8px;font-size:11px;margin-right:4px}}
nav{{display:flex;gap:4px;padding:0 20px;border-bottom:1px solid var(--line);background:var(--panel)}}
nav button{{background:none;border:none;color:var(--mut);padding:10px 14px;cursor:pointer;font-size:13px;
border-bottom:2px solid transparent}} nav button.on{{color:var(--fg);border-color:var(--acc)}}
section{{padding:16px 20px;display:none}} section.on{{display:block}}
.card{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--acc);
border-radius:8px;padding:12px 14px;margin-bottom:10px}}
.chead{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}} .cat{{color:var(--mut);font-size:11px}}
.conf{{color:var(--mut);font-size:11px}} .rat{{color:#c9d1d9;margin:6px 0;font-size:13px}}
.targets{{color:var(--mut);font-size:12px}} details{{margin-top:6px}} summary{{cursor:pointer;color:var(--acc);font-size:12px}}
.prompt{{background:#0d1117;border:1px solid var(--line);border-radius:6px;padding:8px;margin:6px 0;font-size:12px}}
pre.ev{{background:#010409;padding:8px;border-radius:6px;overflow:auto;font-size:11px;color:#8b949e}}
table{{width:100%;border-collapse:collapse;font-size:12px}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}}
th{{color:var(--mut);position:sticky;top:0;background:var(--panel)}} td.tgt{{color:var(--acc);word-break:break-all;max-width:280px}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}}
#g{{width:100%;height:68vh;background:#010409;border:1px solid var(--line);border-radius:8px}}
.leg{{display:flex;gap:10px;flex-wrap:wrap;padding:8px 0;font-size:11px;color:var(--mut)}}
.leg span{{display:inline-flex;align-items:center;gap:4px}} .leg i{{width:10px;height:10px;border-radius:2px;display:inline-block}}
.filter{{margin-bottom:10px}} .filter button{{background:var(--panel);border:1px solid var(--line);color:var(--mut);
border-radius:6px;padding:4px 10px;cursor:pointer;margin-right:4px}} .filter button.on{{color:#fff;border-color:var(--acc)}}
</style></head><body>
<header><h1><span>rcn-mstr</span> &middot; {roots}</h1>
<div class="sub">attack-surface report &middot; {sev_badges}</div></header>
<div class="stats">
<div class="stat"><b>{hosts_total}</b><span>hosts</span></div>
<div class="stat"><b>{hosts_live}</b><span>live</span></div>
<div class="stat"><b>{hosts_direct}</b><span>direct</span></div>
<div class="stat"><b>{hosts_cdn}</b><span>cdn</span></div>
<div class="stat"><b>{ips}</b><span>ips</span></div>
<div class="stat"><b>{services}</b><span>services</span></div>
<div class="stat"><b>{findings}</b><span>findings</span></div>
<div class="stat"><b>{hyp_count}</b><span>hypotheses</span></div>
<div class="stat"><b>{graph_nodes}</b><span>graph nodes</span></div>
<div class="stat"><b>{graph_edges}</b><span>edges</span></div>
</div>
<nav><button class="on" data-t="hyp">Attack hypotheses</button>
<button data-t="find">Findings</button><button data-t="graph">Graph</button></nav>
<section class="on" id="hyp">{hyp_rows}</section>
<section id="find">
<div class="filter" id="sevf">
<button class="on" data-s="all">all</button><button data-s="critical">critical</button>
<button data-s="high">high</button><button data-s="medium">medium</button>
<button data-s="low">low</button><button data-s="info">info</button></div>
<table><thead><tr><th>severity</th><th>conf</th><th>type</th><th>target</th><th>title</th></tr></thead>
<tbody id="ftab">{find_rows}</tbody></table></section>
<section id="graph">
<div class="leg">
<span><i style="background:#4f9"></i>host</span><span><i style="background:#49f"></i>ip</span>
<span><i style="background:#f94"></i>asn</span><span><i style="background:#9f4"></i>cert</span>
<span><i style="background:#f49"></i>favicon</span><span><i style="background:#9cf"></i>service</span>
<span><i style="background:#ccc"></i>tech</span><span><i style="background:#f44"></i>finding</span></div>
<svg id="g"></svg></section>
<script>
var G={gdata};
document.querySelectorAll('nav button').forEach(function(b){{b.onclick=function(){{
 document.querySelectorAll('nav button').forEach(x=>x.classList.remove('on'));b.classList.add('on');
 document.querySelectorAll('section').forEach(s=>s.classList.remove('on'));
 document.getElementById(b.dataset.t).classList.add('on');
 if(b.dataset.t==='graph')draw();}};}});
document.querySelectorAll('#sevf button').forEach(function(b){{b.onclick=function(){{
 document.querySelectorAll('#sevf button').forEach(x=>x.classList.remove('on'));b.classList.add('on');
 var s=b.dataset.s;document.querySelectorAll('#ftab tr').forEach(function(r){{
  r.style.display=(s==='all'||r.dataset.sev===s)?'':'none';}});}};}});
var COL={{host:'#4f9',ip:'#49f',asn:'#f94',cert:'#9f4',favicon:'#f49',service:'#9cf',tech:'#ccc',
finding:'#f44',cname_target:'#fa7',netblock:'#fa7',bucket:'#fc4'}};
var drawn=false;
function draw(){{
 if(drawn)return;drawn=true;
 var svg=document.getElementById('g');var W=svg.clientWidth||900,H=svg.clientHeight||500;
 var N=G.nodes,E=G.edges;var idx={{}};N.forEach(function(n,i){{idx[n.id]=n;
  n.x=W/2+Math.cos(i)*200*Math.random();n.y=H/2+Math.sin(i)*200*Math.random();n.vx=0;n.vy=0;}});
 var deg={{}};E.forEach(function(e){{deg[e.s]=(deg[e.s]||0)+1;deg[e.d]=(deg[e.d]||0)+1;}});
 for(var it=0;it<140;it++){{
  for(var i=0;i<N.length;i++)for(var j=i+1;j<N.length;j++){{
   var a=N[i],b=N[j],dx=a.x-b.x,dy=a.y-b.y,d=Math.sqrt(dx*dx+dy*dy)||1;
   var f=1200/(d*d);a.vx+=dx/d*f;a.vy+=dy/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f;}}
  E.forEach(function(e){{var a=idx[e.s],b=idx[e.d];if(!a||!b)return;
   var dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)||1,f=(d-70)*0.02;
   a.vx+=dx/d*f;a.vy+=dy/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f;}});
  N.forEach(function(n){{n.x+=Math.max(-6,Math.min(6,n.vx));n.y+=Math.max(-6,Math.min(6,n.vy));
   n.vx*=0.85;n.vy*=0.85;n.x=Math.max(10,Math.min(W-10,n.x));n.y=Math.max(10,Math.min(H-10,n.y));}});
 }}
 var s='';E.forEach(function(e){{var a=idx[e.s],b=idx[e.d];if(!a||!b)return;
  s+='<line x1='+a.x+' y1='+a.y+' x2='+b.x+' y2='+b.y+' stroke="#30363d" stroke-width="0.6"/>';}});
 N.forEach(function(n){{var r=3+Math.min(6,(deg[n.id]||0));
  s+='<circle cx='+n.x+' cy='+n.y+' r='+r+' fill="'+(COL[n.t]||'#999')+'"><title>'+n.t+': '+n.l+'</title></circle>';
  if((deg[n.id]||0)>2)s+='<text x='+(n.x+r+2)+' y='+(n.y+3)+' fill="#8b949e" font-size="8">'+n.l+'</text>';}});
 svg.innerHTML=s;
}}
</script></body></html>"""
