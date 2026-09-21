"""Cross-cutting utility helpers.

Currently only :func:`generate_engagement_id`, which produces the
human-readable, filesystem-safe engagement identifier used everywhere
else in AutoRed:

    ``YYYY-MM-DD_NNN-<name>-<target>``

The sequence number ``NNN`` (1-indexed, zero-padded to 3 digits) is
derived by counting existing engagement folders created today.
"""

import re
from datetime import datetime
from pathlib import Path

# Keep alphanumerics, dashes, underscores, and dots. Anything else gets
# collapsed to a single dash so the engagement ID stays filesystem-safe
# (and shell-friendly, since it'll appear in paths, log lines, and CLI
# invocations).
_SAFE_CHARS = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize(value: str, max_len: int = 30) -> str:
    """Strip disallowed characters and cap length."""
    return _SAFE_CHARS.sub("-", value)[:max_len]


def generate_engagement_id(target: str, name: str = "") -> str:
    """Generate an engagement ID of the form ``YYYY-MM-DD_NNN-<name>-<target>``.

    Args:
        target: Target IP / hostname / CIDR. Always included.
        name: Optional human-readable engagement name (e.g. ``"lame-test"``).
            Sanitised to alphanumerics + ``._-``; if empty, it's omitted
            entirely and the ID becomes ``YYYY-MM-DD_NNN-<target>``.

    Returns:
        A filesystem-safe engagement ID string.

    The sequence number is computed by counting existing
    ``engagements/YYYY-MM-DD_*`` folders under the current working
    directory. Call this *before* :func:`init_engagement_folder` to avoid
    off-by-one races.
    """
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    safe_name = _sanitize(name) if name else ""
    safe_target = _sanitize(target)

    # Determine the next sequence number for today.
    engagements_dir = Path("engagements")
    if engagements_dir.exists():
        today_prefix = f"{date_str}_"
        todays = [
            d.name
            for d in engagements_dir.iterdir()
            if d.is_dir() and d.name.startswith(today_prefix)
        ]
        seq = len(todays) + 1
    else:
        seq = 1

    parts = [f"{date_str}_{seq:03d}"]
    if safe_name:
        parts.append(safe_name)
    parts.append(safe_target)
    return "-".join(parts)
