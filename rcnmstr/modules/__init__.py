"""Import every module so they register themselves in base.REGISTRY."""
from . import (  # noqa: F401
    passive, dnsenum, takeover, netintel, probe, portscan, origin, content, jsanalysis, archives, cloud, analysis,
)
