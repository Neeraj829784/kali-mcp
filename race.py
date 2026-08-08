"""Race-condition tester — fire concurrent identical requests to surface
double-spend / TOCTOU logic bugs (e.g. redeeming a coupon many times at once).

Pure `classify_race` is separated from the async `run_race_test` (which takes an
injected client) so the logic is unit-testable offline.
"""
import asyncio
from collections import Counter


def classify_race(statuses: list[int]) -> dict:
    """Summarize a burst of concurrent responses.

    likely_race is True when more than one request 'succeeded' (2xx) — a
    candidate double-spend that a human should confirm against the endpoint's
    intended once-only semantics.
    """
    successes = [s for s in statuses if 200 <= s < 300]
    return {
        "total": len(statuses),
        "success_count": len(successes),
        "status_distribution": dict(Counter(statuses)),
        "likely_race": len(successes) > 1,
    }


async def run_race_test(client, method: str, url: str, headers: dict | None = None,
                        body: str = "", count: int = 20) -> dict:
    """Fire `count` identical requests concurrently and summarize the outcome."""
    async def one() -> int:
        try:
            resp = await client.request(method.upper(), url, headers=headers or {},
                                        content=(body or None))
            return resp.status_code
        except Exception:
            return -1

    results = await asyncio.gather(*[one() for _ in range(count)])
    statuses = [r for r in results if r != -1]
    summary = classify_race(statuses)
    summary.update({
        "url": url,
        "method": method.upper(),
        "requests_sent": count,
        "errors": count - len(statuses),
        "note": (
            "Multiple concurrent requests succeeded — possible race/double-spend. "
            "Confirm this action is supposed to succeed only once."
            if summary["likely_race"] else
            "0-1 successful responses — no obvious race (not necessarily safe)."
        ),
    })
    return summary
