"""Parse nmap XML, profile IoT likelihood, and turn findings into a graded report.

Uses the CRC IoT Scan Kit rule set (rules.py) for finding text, severities and device types.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from .rules import GRADE_TEXT, RULE_PROJECTS, RULES, SEV_WEIGHT, TYPES, UNKNOWN

IOT_VENDORS = ["espressif", "tuya", "raspberry pi", "shelly", "itead", "xiaomi", "amazon technologies",
               "signify", "philips lighting", "sonoff", "hikvision", "dahua", "wyze", "ring", "nest labs"]
LIGHT_OS = ["embedded", "busybox", "lwip", "freertos", "rtos", "vxworks", "contiki", "uclinux", "openwrt",
            "linux 2.6", "linux 3.", "linux 4."]
IOT_PORTS = {80, 443, 1883, 8883, 554, 8554, 5353, 5555, 8008, 8009, 9999, 6668, 37777, 47808, 502}
PORT_RULES = {23: "telnet", 21: "ftp", 5900: "vnc", 5555: "adb", 502: "ot", 47808: "ot", 1883: "mqtt",
              554: "rtsp", 8554: "rtsp", 3389: "rdp", 3306: "db", 5432: "db", 1433: "db", 27017: "db",
              6379: "db", 7547: "tr069", 9999: "localctl", 6668: "localctl"}


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CVE_LINE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d+(?:\.\d+)?)([^\n]*)")


def _add_cve(found: dict, vid: str, cvss, exploit) -> None:
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        score = 0.0
    cur = found.setdefault(vid, {"id": vid, "cvss": 0.0, "exploit": False})
    cur["cvss"] = max(cur["cvss"], score)
    cur["exploit"] = cur["exploit"] or str(exploit).lower() in ("true", "1")


def _parse_vulners(port_el) -> list[dict]:
    """CVE ids + CVSS scores from the vulners NSE script on one port (structured XML first, text fallback)."""
    found: dict[str, dict] = {}
    for sc in port_el.findall("script"):
        if sc.get("id") != "vulners":
            continue
        for t in sc.iter("table"):
            e = {x.get("key"): (x.text or "") for x in t.findall("elem")}
            if CVE_RE.match(e.get("id", "")):
                _add_cve(found, e["id"], e.get("cvss"), e.get("is_exploit"))
        for m in CVE_LINE.finditer(sc.get("output", "")):
            _add_cve(found, m.group(1), m.group(2), "*EXPLOIT*" in m.group(3))
    return sorted(found.values(), key=lambda c: -c["cvss"])


def parse_xml(xml_text: str) -> list[dict]:
    """Return one dict per host that is up. Raises ValueError on unreadable output."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise ValueError(f"Could not read nmap output: {e}") from None
    hosts = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        host = {"ip": None, "mac": None, "vendor": "", "hostnames": [], "os": None, "os_accuracy": None,
                "os_classes": [], "ports": []}
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                host["ip"] = a.get("addr")
            elif a.get("addrtype") == "mac":
                host["mac"], host["vendor"] = a.get("addr"), a.get("vendor", "")
        host["hostnames"] = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        best = h.find("os/osmatch")
        if best is not None:
            host["os"], host["os_accuracy"] = best.get("name"), int(best.get("accuracy", 0))
            host["os_classes"] = [c.get("type", "") for c in best.findall("osclass")]
        for p in h.findall("ports/port"):
            state, svc = p.find("state"), p.find("service")
            if state is None or state.get("state") != "open":
                continue
            host["ports"].append({
                "port": int(p.get("portid")), "proto": p.get("protocol"),
                "service": svc.get("name", "") if svc is not None else "",
                "product": " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else "",
                "cves": _parse_vulners(p),
            })
        if host["ip"]:
            hosts.append(host)
    return hosts


def _classify(host: dict) -> dict:
    """Pick a device type and compute an IoT likelihood with human-readable reasons."""
    vendor = host["vendor"].lower()
    hay = " ".join([vendor, *host["hostnames"], host["os"] or "", *[p["product"] for p in host["ports"]]]).lower()
    ports = {p["port"] for p in host["ports"]}
    best, best_score = UNKNOWN, 0
    for t in TYPES:
        score = 3 * sum(k in hay for k in t["kw"]) + len(ports & set(t["ports"])) + len(set(host["os_classes"]) & set(t["dt"]))
        if score > best_score:
            best, best_score = t, score
    points, reasons = 0, []
    if any(v in vendor for v in IOT_VENDORS):
        points += 3
        reasons.append(f"MAC vendor is a known IoT maker ({host['vendor']})")
    if host["os"] and any(k in host["os"].lower() for k in LIGHT_OS):
        points += 2
        reasons.append(f"Lightweight or embedded OS ({host['os']})")
    hits = sorted(ports & IOT_PORTS)
    if hits:
        points += min(len(hits), 2)
        reasons.append("Typical IoT ports open: " + ", ".join(map(str, hits)))
    if best is not UNKNOWN and best["iot"]:
        points += 2
        reasons.append(f"Matches device type: {best['label']}")
    level = "high" if points >= 4 else "medium" if points >= 2 else "low"
    return {"type_id": best["id"], "type": best["label"], "iot_points": points, "iot_likelihood": level, "reasons": reasons}


def _findings(host: dict, type_id: str) -> list[dict]:
    ids = {PORT_RULES[p["port"]]: p["port"] for p in host["ports"] if p["port"] in PORT_RULES}
    open_ports = {p["port"] for p in host["ports"]}
    if 80 in open_ports and 443 not in open_ports:
        ids.setdefault("httpclear", 80)
    if type_id == "unknown":
        ids.setdefault("unknown", None)
    return [{"id": i, "port": port, **RULES[i], "projects": RULE_PROJECTS.get(i, [])}
            for i, port in sorted(ids.items(), key=lambda kv: -SEV_WEIGHT[RULES[kv[0]]["sev"]])]


def _host_cves(host: dict) -> list[dict]:
    """Merge CVEs across a host's ports (keeping the highest score and the port it came from)."""
    merged: dict[str, dict] = {}
    for p in host["ports"]:
        for c in p.get("cves", []):
            if c["id"] not in merged or c["cvss"] > merged[c["id"]]["cvss"]:
                merged[c["id"]] = {**c, "port": p["port"], "service": p["product"] or p["service"]}
    return sorted(merged.values(), key=lambda c: (-c["cvss"], c["id"]))


def build_report(hosts: list[dict], cve_checked: bool = False) -> dict:
    """Classify hosts, collect findings, and compute a letter grade."""
    out = []
    for h in hosts:
        c = _classify(h)
        f = _findings(h, c["type_id"])
        cves = _host_cves(h)
        if cves:  # one finding per device, at the tier of its worst CVE
            worst = cves[0]["cvss"]
            rid = "cvecrit" if worst >= 9 else "cvehigh" if worst >= 7 else "cvemed"
            f.append({"id": rid, "port": None, **RULES[rid], "projects": RULE_PROJECTS[rid],
                      "detail": f"{len(cves)} known vulnerabilities found. Highest CVSS score: {worst}."})
            f.sort(key=lambda x: -SEV_WEIGHT[x["sev"]])
        out.append({**h, **c, "findings": f, "cves": cves, "cve_count": len(cves),
                    "risk": sum(SEV_WEIGHT[x["sev"]] for x in f)})
    out.sort(key=lambda h: (-h["risk"], h["ip"]))

    net_findings = []
    iot = [h for h in out if h["iot_likelihood"] != "low"]
    if iot and any(h["type_id"] == "computer" for h in out):
        net_findings.append({"id": "flat", **RULES["flat"], "port": None, "projects": RULE_PROJECTS["flat"]})

    counts = {s: 0 for s in SEV_WEIGHT}
    fixes: dict[str, dict] = {}
    for f in [*net_findings, *(x for h in out for x in h["findings"])]:
        counts[f["sev"]] += 1
        fixes.setdefault(f["id"], {**f, "count": 0})["count"] += 1
    penalty = sum(SEV_WEIGHT[s] * n for s, n in counts.items()) * 6
    score = max(0, 100 - penalty)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    top = sorted(fixes.values(), key=lambda f: -(SEV_WEIGHT[f["sev"]] * f["count"]))[:5]
    return {"summary": {"hosts": len(out), "iot_devices": len(iot), "counts": counts, "score": score,
                        "grade": grade, "grade_text": GRADE_TEXT[grade],
                        "cve_checked": cve_checked, "cves_total": sum(h["cve_count"] for h in out)},
            "hosts": out, "network_findings": net_findings, "top_fixes": top,
            "note": ("Vulnerabilities are matched by software version number through the vulners database, so they can include "
                     "false alarms (vendors sometimes patch without changing the version) and miss flaws in services with no "
                     "version detected. If a device shows none, its services may not report versions, or the lookup could not "
                     "reach the internet." if cve_checked else "Vulnerability lookup was turned off for this scan.")}
