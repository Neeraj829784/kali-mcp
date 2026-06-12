"""Structured output parsers for tool results."""
import json
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_str: str) -> dict:
    """Parse nmap -oX output into a structured dict."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {"raw": xml_str, "parse_error": True}

    hosts = []
    for host in root.findall("host"):
        state = host.find("status")
        addr = host.find("address")
        if state is None or addr is None:
            continue
        entry = {
            "ip": addr.get("addr"),
            "state": state.get("state"),
            "hostnames": [h.get("name") for h in host.findall("hostnames/hostname")],
            "ports": [],
            "os": [],
        }
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            svc = port.find("service")
            entry["ports"].append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": state_el.get("state") if state_el is not None else "unknown",
                "service": svc.get("name") if svc is not None else "",
                "version": (
                    f"{svc.get('product','')} {svc.get('version','')}".strip()
                    if svc is not None else ""
                ),
            })
        for osmatch in host.findall("os/osmatch"):
            entry["os"].append({
                "name": osmatch.get("name"),
                "accuracy": osmatch.get("accuracy"),
            })
        hosts.append(entry)
    return {"hosts": hosts, "total": len(hosts)}


def parse_nuclei_jsonl(jsonl_str: str) -> dict:
    """Parse nuclei -jsonl output into structured findings."""
    findings = []
    for line in jsonl_str.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            findings.append({
                "template": obj.get("template-id", ""),
                "name": obj.get("info", {}).get("name", ""),
                "severity": obj.get("info", {}).get("severity", ""),
                "host": obj.get("host", ""),
                "matched": obj.get("matched-at", ""),
                "tags": obj.get("info", {}).get("tags", []),
            })
        except json.JSONDecodeError:
            continue
    by_severity: dict[str, list] = {}
    for f in findings:
        by_severity.setdefault(f["severity"], []).append(f)
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "findings": findings,
    }
