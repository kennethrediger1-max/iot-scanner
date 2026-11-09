import pytest
from app.core import roe
from app.core.parser import build_report, parse_xml

XML = """<nmaprun><host><status state="up"/><address addr="192.168.1.50" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Espressif"/>
<ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="lwIP"/></port></ports>
<os><osmatch name="Linux 3.2" accuracy="90"><osclass type="specialized"/></osmatch></os></host></nmaprun>"""


def test_parse_and_report():
    r = build_report(parse_xml(XML))
    h = r["hosts"][0]
    assert h["iot_likelihood"] == "high"
    assert {"telnet", "httpclear"} <= {f["id"] for f in h["findings"]}
    assert r["summary"]["grade"] in "ABCDF"


def test_roe_gate():
    with pytest.raises(roe.RoEError):
        roe.issue_token([], "nope", "")
    ok = roe.issue_token([i["id"] for i in roe.ROE_ITEMS], roe.CONFIRM_PHRASE.lower(), "Sam")
    assert roe.verify_token(ok["token"])["n"] == "Sam"
    with pytest.raises(roe.RoEError):
        roe.verify_token(ok["token"] + "x")


@pytest.mark.parametrize("bad", ["8.8.8.8", "127.0.0.1", "10.0.0.0/8", "--script=x", "10.0.0.1; rm"])
def test_targets_rejected(bad):
    with pytest.raises(roe.RoEError):
        roe.validate_targets([bad])


VULN_XML = """<nmaprun><host><status state="up"/><address addr="192.168.1.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.4"/>
<script id="vulners" output="x"><table key="cpe:/a:openbsd:openssh:7.4">
<table><elem key="is_exploit">true</elem><elem key="cvss">9.8</elem><elem key="id">CVE-2018-15473</elem><elem key="type">cve</elem></table>
<table><elem key="cvss">5.0</elem><elem key="id">EDB-ID:45233</elem><elem key="type">exploitdb</elem></table></table></script>
</port></ports></host></nmaprun>"""


def test_cve_lookup():
    h = build_report(parse_xml(VULN_XML), cve_checked=True)["hosts"][0]
    assert [c["id"] for c in h["cves"]] == ["CVE-2018-15473"] and h["cves"][0]["exploit"]
    assert "cvecrit" in {f["id"] for f in h["findings"]}
