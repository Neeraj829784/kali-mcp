"""Tests for the race-condition tester (race.py) — offline."""
import pytest

import race as R


def test_classify_race_multiple_success():
    s = R.classify_race([200, 200, 200, 409, 409])
    assert s["success_count"] == 3 and s["likely_race"] is True
    assert s["status_distribution"][200] == 3


def test_classify_race_single_success():
    s = R.classify_race([200, 409, 409, 409])
    assert s["success_count"] == 1 and s["likely_race"] is False


class _AllOKClient:
    async def request(self, method, url, headers=None, content=None):
        from types import SimpleNamespace
        return SimpleNamespace(status_code=200, content=b"ok")


class _OnlyOneWinsClient:
    """First request succeeds; the rest get 409 Conflict (properly serialized)."""
    def __init__(self):
        self._served = 0

    async def request(self, method, url, headers=None, content=None):
        from types import SimpleNamespace
        self._served += 1
        return SimpleNamespace(status_code=(200 if self._served == 1 else 409), content=b"")


@pytest.mark.asyncio
async def test_run_race_test_detects_double_spend():
    out = await R.run_race_test(_AllOKClient(), "POST", "https://x/redeem", count=10)
    assert out["requests_sent"] == 10
    assert out["success_count"] == 10 and out["likely_race"] is True


@pytest.mark.asyncio
async def test_run_race_test_properly_serialized():
    out = await R.run_race_test(_OnlyOneWinsClient(), "POST", "https://x/redeem", count=10)
    assert out["success_count"] == 1 and out["likely_race"] is False
