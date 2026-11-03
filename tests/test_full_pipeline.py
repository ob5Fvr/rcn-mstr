"""All default modules in deep mode against the mock internet: nothing crashes end-to-end."""
import asyncio

import pytest

from rcnmstr.selftest import run_self_test


@pytest.mark.asyncio
async def test_all_modules_deep_no_crashes(tmp_path):
    import rcnmstr.engine as E
    captured = {}
    orig = E.run

    async def wrap(cfg):
        ctx = await orig(cfg)
        captured["ctx"] = ctx
        return ctx
    E.run = wrap
    try:
        # modules=[] in selftest means "use defaults"; pass the FULL default set incl. deep-only ones
        rc = await run_self_test(str(tmp_path / "full"),
                                 modules=["resolve", "dnsrecords", "brute", "permute", "takeover", "netintel",
                                          "portscan", "probe", "origin", "waf", "content", "js", "related",
                                          "analysis", "correlate"],
                                 mode="deep")
    finally:
        E.run = orig
    ctx = captured["ctx"]
    # no module may have recorded an unhandled crash
    crashed = {m: st["errors"] for m, st in ctx.module_status.items() if st.get("errors")}
    assert not crashed, f"modules crashed: {crashed}"
    # core signals still present
    assert ctx.hypotheses, "expected hypotheses"
    assert ctx.graph.stats()["nodes"] > 0
    assert ctx.stats["dns_mode"] == "udp"
