"""Browser dashboard (live ops console) — spec 2026-09-27-dashboard-liveops."""
from autored.dashboard.api import create_app, state_summary
from autored.dashboard.bridge import DashboardBridge

__all__ = ["create_app", "state_summary", "DashboardBridge"]
