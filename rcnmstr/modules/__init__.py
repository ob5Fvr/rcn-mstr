"""Import every module so they register themselves in base.REGISTRY."""
from . import (  # noqa: F401
    passive, dnsenum, takeover, netintel, probe, waf, portscan, origin, content, jsanalysis, archives, cloud, analysis, correlate,
)
