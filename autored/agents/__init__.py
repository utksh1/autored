"""AutoRed agents — LangGraph node modules.

Phase 1: ``recon`` (LLM-planned recon loop) and ``report`` (Phase 1
terminal stub; Phase 6 replaces with the full Report Agent).

Phase 2-6 plans add their own node modules here (``vuln``, ``exploit``,
``postex``, ``lateral``, ``cleanup``, full ``report``).
"""
from __future__ import annotations
