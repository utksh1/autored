"""AutoRed utility helpers."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from autored.logging import get_logger

log = get_logger("utils")


def generate_engagement_id(target: str, name: str = "") -> str:
    """Generate an engagement ID like '2026-09-23_001-<name>-<target>'.

    The numeric counter (001, 002, ...) increments per-day by scanning
    existing engagements/ subdirectories starting with the date prefix.
    """
    today = datetime.utcnow().strftime("%Y-%m-%d")
    engagements = Path("engagements")
    counter = 1
    if engagements.exists():
        for d in sorted(engagements.iterdir()):
            if d.is_dir() and d.name.startswith(f"{today}_"):
                try:
                    n = int(d.name[len(today) + 1 : len(today) + 4])
                    if n >= counter:
                        counter = n + 1
                except ValueError:
                    continue

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", name)[:30] if name else ""
    safe_target = re.sub(r"[^a-zA-Z0-9._-]", "-", target)[:30]
    parts = [f"{today}_{counter:03d}"]
    if safe_name:
        parts.append(safe_name)
    parts.append(safe_target)
    return "-".join(parts)
