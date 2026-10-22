"""SOC connector framework: fetch, parse, normalize to ECS, forward.

Public surface is intentionally small at this milestone — connectors and forwarders are
imported through the registries in their own packages, not from here.
"""

from soc_connectors.version import __version__

__all__ = ["__version__"]
