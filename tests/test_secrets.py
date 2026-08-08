"""Tests for the secrets scanner (secrets_scan.py) — offline.

Token literals are assembled at runtime from fragments so this source file
contains no contiguous secret-looking strings (avoids GitHub push protection /
secret-scanning false positives). The concatenated values still exercise the
detection regexes at test time.
"""
import secrets_scan as S

# Assembled fakes (never a contiguous secret token in source).
_AWS = "AKIA" + "IOSFODNN7EXAMPLE"                    # AKIA + 16
_GOOGLE = "AIza" + "B" * 35                           # AIza + 35
_GITHUB = "ghp_" + "0" * 36                           # ghp_ + 36
_STRIPE = "sk_" + "live_" + "0" * 25                  # sk_live_ + 25


def test_detects_common_key_types():
    text = (
        f"const aws='{_AWS}';\n"
        f"var g='{_GOOGLE}';\n"
        f"token='{_GITHUB}';\n"
        f"stripe='{_STRIPE}';\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
    )
    types = {f["type"] for f in S.scan_secrets(text)}
    assert "AWS Access Key ID" in types
    assert "Google API Key" in types
    assert "GitHub Token" in types
    assert "Stripe Live Secret Key" in types
    assert "Private Key Block" in types


def test_generic_assignment_and_redaction():
    found = S.scan_secrets("api_key: 'supersecretvalue123'", source="app.js")
    assert any(f["type"] == "Generic secret assignment" for f in found)
    f = found[0]
    assert f["source"] == "app.js"
    # value is redacted (not shown in full)
    assert "supersecretvalue123" not in f["match_redacted"]
    assert "..." in f["match_redacted"]


def test_clean_text_no_findings():
    assert S.scan_secrets("just some normal javascript code; var x = 1;") == []


def test_dedupe_repeated_secret():
    text = f"k='{_AWS}'; again='{_AWS}';"
    aws = [f for f in S.scan_secrets(text) if f["type"] == "AWS Access Key ID"]
    assert len(aws) == 1  # same value reported once
