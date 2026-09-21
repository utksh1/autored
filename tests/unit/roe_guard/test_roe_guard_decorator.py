# tests/unit/roe_guard/test_roe_guard_decorator.py
import pytest
from autored.roe_guard import roe_guard, RoEViolation, register_roe
from autored.models.roe import RulesOfEngagement


@pytest.fixture
def sandbox_roe():
    roe = RulesOfEngagement(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
        hitl_mode="auto_approve",
    )
    register_roe("test-eng", roe)
    return roe


@pytest.mark.asyncio
async def test_decorator_allows_in_scope(sandbox_roe):
    # _categorize_call maps by function name, so the decorated function
    # is named after a real tool (nmap_scan -> "recon") to exercise the
    # happy path: RoE registered, category in allowed_categories, target
    # in scope -> function executes.
    @roe_guard(allowed_categories=["recon"])
    async def nmap_scan(target: str, engagement_id: str = ""):
        return {"target": target}

    result = await nmap_scan(target="10.10.10.5", engagement_id="test-eng")
    assert result == {"target": "10.10.10.5"}


@pytest.mark.asyncio
async def test_decorator_blocks_out_of_scope():
    roe = RulesOfEngagement(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["10.10.10.0/24"], allowed_techniques=["*"],
        persistence_allowed=False, evasion_allowed=False,
        exfiltration_allowed=False, kernel_exploits_allowed=False,
    )
    register_roe("test-eng-2", roe)

    @roe_guard(allowed_categories=["recon"])
    async def nmap_scan(target: str, engagement_id: str = ""):
        return {"target": target}

    with pytest.raises(RoEViolation) as exc:
        await nmap_scan(target="8.8.8.8", engagement_id="test-eng-2")
    assert "not in allowed_ips" in str(exc.value)


@pytest.mark.asyncio
async def test_decorator_blocks_wrong_category(sandbox_roe):
    # Verifies category blocking via _categorize_call: a tool whose
    # category is NOT in allowed_categories must be blocked, even when
    # the target itself is in scope. sqlmap_run -> "exploit", and
    # allowed_categories=["recon"], so the call must raise RoEViolation.
    @roe_guard(allowed_categories=["recon"])
    async def sqlmap_run(target: str, engagement_id: str = ""):
        return {}

    with pytest.raises(RoEViolation) as exc:
        await sqlmap_run(target="10.10.10.5", engagement_id="test-eng")
    assert "not allowed for category" in str(exc.value)
    assert "exploit" in str(exc.value)
