from __future__ import annotations

# Spec §16 lists both webapp.py and discovery.py. DiscoveredPath lives in webapp.py;
# this file re-exports for discovery-style imports.
from autored.models.webapp import DiscoveredPath

__all__ = ["DiscoveredPath"]
