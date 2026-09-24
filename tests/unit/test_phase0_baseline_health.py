"""Phase 0 baseline health checks.

These tests assert that every existing subagent file imports cleanly
after Phase 0 foundation work, that every asyncio.gather call site
passes return_exceptions=True, and that refusal detection is centralized
in router.py only (no duplicated marker lists).
"""
from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest


SUBAGENTS_DIR = Path(__file__).parent.parent.parent / "autored" / "subagents"


@pytest.mark.xfail(
    reason=(
        "Phase 2+ tools not yet implemented (subagents cvematcher, "
        "exploitfinder, etc. import autored.tools.nvd/sqlmap/etc. which "
        "land in Phases 2-5)"
    )
)
def test_phase2plus_subagents_import_cleanly():
    """Phase 2+ subagent modules must import without ImportError.

    These 22 subagents reference Phase 2-5 tool modules
    (``autored.tools.nvd``, ``autored.tools.searchsploit``,
    ``autored.tools.sqlmap``, ``autored.tools.hydra``,
    ``autored.tools.metasploit``, ``autored.tools.custom``,
    ``autored.tools.linpeas``, ``autored.tools.winpeas``,
    ``autored.tools.bloodhound``, ``autored.tools.mimikatz``,
    ``autored.tools.secretsdump``, ``autored.tools.certipy``,
    ``autored.tools.persistence``, ``autored.tools.evasion``,
    ``autored.tools.exfil``, ``autored.tools.impacket_remote``,
    ``autored.tools.crackmapexec``, ``autored.tools.tunnel``,
    ``autored.tools.cleanup``) that don't exist yet. xfailed until
    Phase 2-5 land their tools.
    """
    phase2plus = {
        "artifactremover", "bruteagent", "credharvester", "customagent",
        "cvematcher", "evasionagent", "execsummarywriter", "exfilagent",
        "exploitfinder", "hypothesiscritic", "lessonextractor",
        "linuxenum", "mitremapper", "msfagent", "persistenceagent",
        "pivotexecutor", "privescfinder", "sqliagent",
        "techreportwriter", "tunnelsetup", "verificationscanner",
        "windowsenum",
    }
    failures = []
    for py in sorted(SUBAGENTS_DIR.glob("*.py")):
        if py.name == "__init__.py":
            continue
        if py.stem not in phase2plus:
            continue
        mod_name = f"autored.subagents.{py.stem}"
        try:
            importlib.import_module(mod_name)
        except Exception as exc:
            failures.append(f"{mod_name}: {type(exc).__name__}: {exc}")
    assert not failures, "Phase 2+ subagent import failures:\n" + "\n".join(failures)


def test_phase1_subagents_import_cleanly():
    """Phase 1 subagent modules must import without ImportError.

    These 5 subagents (``portscan``, ``webenum``, ``subdomainenum``,
    ``dnsenum``, ``vhostenum``) only depend on Phase 1 tool modules
    (``autored.tools.nmap``, ``autored.tools.naabu``, etc.) which
    shipped with Phase 1. This test replaces the old combined xfail
    (which marked *all* subagents as "Phase 1 tools not yet
    implemented" — stale once Phase 1 landed) and gives finer-grained
    signal as Phase 2-5 land their tools.
    """
    phase1 = {"portscan", "webenum", "subdomainenum", "dnsenum", "vhostenum"}
    failures = []
    for py in sorted(SUBAGENTS_DIR.glob("*.py")):
        if py.name == "__init__.py":
            continue
        if py.stem not in phase1:
            continue
        mod_name = f"autored.subagents.{py.stem}"
        try:
            importlib.import_module(mod_name)
        except Exception as exc:
            failures.append(f"{mod_name}: {type(exc).__name__}: {exc}")
    assert not failures, "Phase 1 subagent import failures:\n" + "\n".join(failures)


def test_gather_call_sites_use_return_exceptions():
    """Review Focus #5 — every asyncio.gather( must pass return_exceptions=True."""
    violations = []
    for py in sorted(SUBAGENTS_DIR.glob("*.py")):
        text = py.read_text()
        # Find every asyncio.gather( call and check the same call has return_exceptions=True.
        for m in re.finditer(r"asyncio\.gather\([^)]*\)", text, re.DOTALL):
            call = m.group(0)
            if "return_exceptions=True" not in call:
                violations.append(f"{py.name}: {call[:80]}...")
    assert not violations, (
        "asyncio.gather calls missing return_exceptions=True:\n"
        + "\n".join(violations)
    )


def test_refusal_detection_is_centralized():
    """Review Focus #4 — only one _is_refusal definition, in router.py."""
    autored_root = SUBAGENTS_DIR.parent
    duplicate_locations = []
    for py in sorted(autored_root.rglob("*.py")):
        if "router.py" in str(py):
            continue
        text = py.read_text()
        # Look for `def _is_refusal` (definition) — not just calls.
        if re.search(r"def\s+_is_refusal\s*\(", text):
            duplicate_locations.append(str(py))
    assert not duplicate_locations, (
        "_is_refusal defined outside router.py:\n"
        + "\n".join(duplicate_locations)
    )


def test_subdomainenum_imports_amass_from_correct_module():
    """The Phase 1 plan has a bug — subdomainenum imports amass_enum from
    autored.tools.subfinder, but amass_enum lives in autored.tools.amass.
    Verify the fix is in place."""
    text = (SUBAGENTS_DIR / "subdomainenum.py").read_text()
    assert "from autored.tools.amass import" in text, (
        "subdomainenum.py must import amass_enum from autored.tools.amass"
    )
    assert "from autored.tools.subfinder import amass_enum" not in text, (
        "subdomainenum.py still has the buggy import"
    )


def test_subagents_init_exports_all_modules():
    """__init__.py should auto-discover all subagent modules, not hand-curate 4 names."""
    text = (SUBAGENTS_DIR / "__init__.py").read_text()
    # Either explicit `from .X import Y` for every module, OR pkgutil.walk_packages.
    assert "pkgutil" in text or len(re.findall(r"^from \.", text, re.MULTILINE)) >= 20, (
        "subagents/__init__.py does not auto-discover or export all 27 modules"
    )
