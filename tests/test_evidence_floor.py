"""Tests for evidence-anchored confidence floor (Tier 1 FP reduction)."""
import findings as F


def test_caps_confidence_without_evidence():
    f = F._finding("h", "Some finding", F.HIGH, "", "nuclei", confidence=F.CONF_HIGH)
    out = F.apply_evidence_floor([f])
    assert out[0]["confidence"] == F.CONF_LOW
    assert out[0]["confidence_capped"] is True


def test_caps_confidence_with_trivial_evidence():
    f = F._finding("h", "Some finding", F.HIGH, "x", "nuclei", confidence=F.CONF_MEDIUM)
    out = F.apply_evidence_floor([f])
    assert out[0]["confidence"] == F.CONF_LOW


def test_keeps_confidence_with_evidence():
    f = F._finding("h", "SQLi", F.CRITICAL, "Parameter id is injectable (boolean-based)",
                   "sqlmap", confidence=F.CONF_HIGH)
    out = F.apply_evidence_floor([f])
    assert out[0]["confidence"] == F.CONF_HIGH
    assert "confidence_capped" not in out[0]


def test_corroboration_exempt_from_cap():
    """A finding seen by 2+ tools is evidence-anchored even with short evidence."""
    f = F._finding("h", "Open port 80", F.INFO, "", "nmap", confidence=F.CONF_HIGH)
    f["tools"] = ["nmap", "masscan"]
    out = F.apply_evidence_floor([f])
    assert out[0]["confidence"] == F.CONF_HIGH


def test_low_confidence_unchanged():
    f = F._finding("h", "x", F.LOW, "", "nikto", confidence=F.CONF_LOW)
    out = F.apply_evidence_floor([f])
    assert out[0]["confidence"] == F.CONF_LOW
    # already low — not flagged as capped
    assert "confidence_capped" not in out[0]


def test_idempotent():
    f = F._finding("h", "x", F.HIGH, "", "nuclei", confidence=F.CONF_HIGH)
    once = F.apply_evidence_floor([dict(f)])
    twice = F.apply_evidence_floor(once)
    assert twice[0]["confidence"] == F.CONF_LOW


def test_extract_findings_applies_floor():
    """A nuclei finding with empty matched-at evidence is capped at extraction."""
    # nuclei JSONL with no matched-at -> evidence empty -> capped to low
    jsonl = '{"host":"h","template-id":"t","info":{"name":"Test","severity":"high"},"matched-at":""}'
    out = F.extract_findings("nuclei", jsonl, "h")
    assert len(out) == 1
    assert out[0]["confidence"] == F.CONF_LOW
    assert out[0]["confidence_capped"] is True


def test_dedup_applies_floor():
    a = F._finding("h", "Lonely finding", F.HIGH, "", "nuclei", confidence=F.CONF_HIGH)
    out = F.dedup_findings([a])
    assert out[0]["confidence"] == F.CONF_LOW
