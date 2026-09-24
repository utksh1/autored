"""AutoRed subagents — auto-discovered.

Phase 1-6 plans add subagents to this directory; __init__ discovers them
via pkgutil so adding a new file is enough.
"""
from __future__ import annotations

import pkgutil

__all__ = [
    name for _, name, _ in pkgutil.walk_packages(__path__, prefix=f"{__name__}.")
]
