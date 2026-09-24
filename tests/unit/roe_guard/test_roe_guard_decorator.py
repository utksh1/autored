from __future__ import annotations

import pytest

from autored.roe_guard import roe_guard, RoEViolation, register_roe
from autored.config import RulesOfEngagement


def _sandbox_roe(**overrides) -> RulesOfEngagement:
    base = dict(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["10.10.10.0/24"], allowed_techniques=["*"],
        persistence_allowed=False, evasion_allowed=False,
        exfiltration_allowed=False, data_destruction_allowed=False,
        kernel_exploits_allowed=False, hitl_mode="always_ask",
    )
    base.update(overrides)
    return RulesOfEngagement(**base)


@pytest.mark.asyncio
async def test_decorator_allows_in_scope():
    register_roe("e1", _sandbox_roe())

    @roe_guard(allowed_categories=["recon"])
    async def fake_scan(target: str, engagement_id: str = ""):
        return {"scanned": target}

    result = await fake_scan(target="10.10.10.5", engagement_id="e1")
    assert result == {"scanned": "10.10.10.5"}


@pytest.mark.asyncio
async def test_decorator_blocks_out_of_scope():
    register_roe("e2", _sandbox_roe())

    @roe_guard(allowed_categories=["recon"])
    async def fake_scan(target: str, engagement_id: str = ""):
        return {"scanned": target}

    with pytest.raises(RoEViolation) as exc:
        await fake_scan(target="8.8.8.8", engagement_id="e2")
    assert "8.8.8.8" in exc.value.reason


@pytest.mark.asyncio
async def test_decorator_blocks_wrong_category():
    register_roe("e3", _sandbox_roe())

    @roe_guard(allowed_categories=["recon"])
    async def fake_scan(target: str, engagement_id: str = ""):
        return {"scanned": target}

    # The decorator categorizes by function NAME, not by what's actually called.
    # Renaming the function to something mapped to "persistence" should block.
    fake_scan.__name__ = "cron_modify"
    with pytest.raises(RoEViolation):
        await fake_scan(target="10.10.10.5", engagement_id="e3")


@pytest.mark.asyncio
async def test_decorator_raises_when_no_roe_registered():
    @roe_guard(allowed_categories=["recon"])
    async def fake_scan(target: str, engagement_id: str = ""):
        return {"scanned": target}

    with pytest.raises(RoEViolation) as exc:
        await fake_scan(target="10.10.10.5", engagement_id="nonexistent")
    assert "No RoE registered" in exc.value.reason
