"""
Webhook notifications — fire-and-forget HTTP POST on critical findings.

Supports any endpoint that accepts JSON (Slack, Discord, Teams, custom).
Configure via env vars:
  KALI_MCP_WEBHOOK_URL          — full URL to POST to (empty = disabled)
  KALI_MCP_WEBHOOK_MIN_SEVERITY — minimum severity to notify (default: critical)

Slack/Discord example payload shape is auto-detected from the URL.
"""
from __future__ import annotations
import asyncio
import json
import logging
import re

from config import WEBHOOK_URL, WEBHOOK_MIN_SEVERITY

_log = logging.getLogger(__name__)

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "ℹ️",
}


def _should_notify(severity: str) -> bool:
    if not WEBHOOK_URL:
        return False
    return _SEV_RANK.get(severity.lower(), 0) >= _SEV_RANK.get(WEBHOOK_MIN_SEVERITY.lower(), 4)


def _build_payload(finding: dict, engagement_name: str = "") -> dict:
    """Build the JSON payload.  Auto-detects Slack/Discord from URL."""
    sev = finding.get("severity", "info").lower()
    emoji = _SEV_EMOJI.get(sev, "⚠️")
    title = finding.get("title", "Finding")
    host = finding.get("host", "unknown")
    tool = finding.get("tool", "")
    evidence = finding.get("evidence", "")[:200]
    eng = f" [{engagement_name}]" if engagement_name else ""

    # Slack-style (has /services/ in URL)
    if "hooks.slack.com" in WEBHOOK_URL or "/services/" in WEBHOOK_URL:
        return {
            "text": f"{emoji} *{sev.upper()} Finding{eng}*: {title}",
            "attachments": [{
                "color": {"critical": "danger", "high": "warning"}.get(sev, "good"),
                "fields": [
                    {"title": "Host", "value": host, "short": True},
                    {"title": "Tool", "value": tool, "short": True},
                    {"title": "Evidence", "value": evidence, "short": False},
                ],
            }],
        }

    # Discord-style (has /webhooks/ in URL)
    if "/webhooks/" in WEBHOOK_URL:
        color_map = {"critical": 15158332, "high": 15105570, "medium": 16776960,
                     "low": 3066993, "info": 3447003}
        return {
            "embeds": [{
                "title": f"{emoji} {sev.upper()}: {title}",
                "description": f"**Host:** {host}\n**Tool:** {tool}\n**Evidence:** {evidence}",
                "color": color_map.get(sev, 8421504),
                "footer": {"text": f"kali-mcp{eng}"},
            }]
        }

    # Generic JSON — works with Teams, custom webhooks, etc.
    return {
        "severity": sev,
        "title": title,
        "host": host,
        "tool": tool,
        "evidence": evidence,
        "engagement": engagement_name,
        "emoji": emoji,
    }


async def notify(finding: dict, engagement_name: str = "") -> None:
    """Send a webhook notification for a finding. Fire-and-forget — never raises."""
    if not _should_notify(finding.get("severity", "info")):
        return
    try:
        import httpx
        payload = _build_payload(finding, engagement_name)
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                WEBHOOK_URL,
                content=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code >= 400:
                _log.warning("Webhook returned %s: %s", resp.status_code, resp.text[:200])
    except Exception as e:
        _log.warning("Webhook notification failed: %s", e)
