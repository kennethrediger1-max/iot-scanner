"""Finding rules (severity, plain-language why/fix) and device types. Ported from the CRC IoT Scan Kit."""
from __future__ import annotations

SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _r(sev, title, why, fix):
    return {"sev": sev, "title": title, "why": why, "fix": fix}


RULES: dict[str, dict] = {
 "telnet": _r("high", "Telnet is turned on", "Telnet sends usernames and passwords in clear text. It is the main way IoT botnets such as Mirai take over cameras and routers.", "Turn off Telnet in the device settings and manage it over HTTPS or SSH. If Telnet cannot be turned off, replace the device or move it to an isolated network."),
 "ftpanon": _r("high", "Anonymous FTP login allowed", "Anyone on the network can read, and sometimes write, files on this device without a password.", "Disable anonymous FTP. Turn off FTP entirely if nobody uses it; use SFTP or the vendor's secure file sharing instead."),
 "ftp": _r("medium", "FTP service running", "FTP sends passwords in clear text.", "Turn off FTP if it is not needed, or replace it with SFTP."),
 "smbv1": _r("high", "SMBv1 file sharing enabled", "SMBv1 is the protocol abused by WannaCry and NotPetya ransomware. Microsoft has deprecated it.", "Disable SMBv1 on the device (on NAS units this is usually \"minimum SMB protocol\" in file services settings). Require SMB2 or SMB3."),
 "snmpdefault": _r("high", "SNMP answers to the default \"public\" community", "Anyone on the network can read device details, and some devices also allow configuration changes with default communities.", "Change the SNMP community string or turn SNMP off. If monitoring needs it, use SNMPv3 with authentication."),
 "snmp": _r("medium", "SNMP service exposed", "SNMP v1/v2c uses a shared password sent in clear text.", "Turn SNMP off if nothing monitors this device, or switch to SNMPv3."),
 "vnc": _r("high", "VNC remote desktop exposed", "VNC often runs with a weak password or none, giving full screen control.", "Turn off VNC or restrict it to an admin network and require a strong password."),
 "adb": _r("high", "Android Debug Bridge open", "ADB on port 5555 gives anyone on the network a command shell on the device. Common on cheap TV boxes and signage players.", "Turn off developer options / network debugging on the device, or remove the device from the network."),
 "ot": _r("high", "Building control protocol on the office network", "Modbus and BACnet have no authentication. Anyone on the network can read and change HVAC, lighting, or access settings.", "Move building controls to a separate network or VLAN that only the facilities vendor can reach."),
 "mqttopen": _r("high", "MQTT broker accepts anonymous clients", "Anyone can read sensor data and send commands to smart devices through this broker.", "Require a username and password on the broker and enable TLS (port 8883)."),
 "mqtt": _r("medium", "Unencrypted MQTT broker", "MQTT on port 1883 sends device messages and credentials in clear text.", "Enable TLS on the broker (port 8883) and require authentication."),
 "httpclear": _r("medium", "Admin web page without encryption", "The device's web interface runs over plain HTTP, so the admin password crosses the network in clear text.", "Enable HTTPS in the device settings and turn off HTTP, or manage the device only from a trusted wired connection."),
 "rtsp": _r("medium", "Camera video stream reachable", "RTSP streams are often viewable with default or no credentials.", "Confirm the stream requires a strong, non-default password. Put cameras on their own network segment."),
 "rdp": _r("medium", "Remote Desktop (RDP) open", "RDP is a top ransomware entry point when passwords are weak or reused.", "Require Network Level Authentication and MFA, and allow RDP only from admin machines or through a VPN."),
 "db": _r("medium", "Database port reachable from the network", "Databases reachable by every device on the network are at risk from a single compromised laptop or IoT device.", "Bind the database to localhost or restrict access with a host firewall."),
 "tr069": _r("medium", "ISP remote management (TR-069) open", "TR-069 lets the internet provider manage the router; flaws in it have been used to take over routers at scale.", "Ask the ISP whether it is needed. Make sure router firmware is current."),
 "localctl": _r("medium", "Smart plug or switch with local control port", "Ports 9999 (Kasa) and 6668 (Tuya) accept commands from any device on the network without a password.", "Put smart-home devices on a guest or IoT network separate from staff computers."),
 "upnp": _r("medium", "UPnP enabled on the router", "UPnP lets any device on the network open ports to the internet without the owner knowing. Malware uses this to expose itself.", "Turn off UPnP in the router settings unless a specific need is documented."),
 "upnpdev": _r("low", "Device advertises itself with UPnP", "UPnP reveals model and firmware details to anyone on the network.", "Turn off UPnP on the device if the setting exists."),
 "certexp": _r("low", "Expired TLS certificate", "Staff learn to click through browser warnings, which makes real attacks easier to miss.", "Renew or replace the certificate."),
 "certself": _r("low", "Self-signed TLS certificate", "Browsers cannot verify the device, so staff get used to ignoring warnings.", "Acceptable for a small office device if documented. Replace with a trusted certificate where the device supports it."),
 "unknown": _r("low", "Device could not be identified", "Unknown devices cannot be patched or tracked. They may be personal devices, forgotten hardware, or something that should not be there.", "Find the device (check the router's client list for its MAC address) and record its owner, or remove it."),
 "cvecrit": _r("critical", "Software with critical known vulnerabilities (CVSS 9+)", "These flaws are publicly documented and many have working exploits.", "Update the firmware or software to the current vendor release. If no update exists, replace or isolate the device."),
 "cvehigh": _r("high", "Software with high-severity known vulnerabilities (CVSS 7-8.9)", "Publicly documented flaws that attackers can look up by version number.", "Update the firmware or software to the current vendor release."),
 "cvemed": _r("medium", "Software with medium-severity known vulnerabilities", "Lower-risk flaws that still indicate outdated software.", "Include in the next scheduled update cycle."),
 "flat": _r("high", "IoT devices share a network with staff computers", "If one camera, printer, or smart device is compromised, the attacker can reach every laptop and file server directly.", "Create a separate VLAN or guest network for IoT devices and block it from reaching staff computers. Most business routers and access points support this."),
}

# Practitioner catalog projects that help fix each finding (validated against the catalog in tests).
RULE_PROJECTS: dict[str, list[str]] = {
    "telnet": ["network-edge-13", "endpoints-de-06"], "ftp": ["network-edge-13"], "ftpanon": ["network-edge-13"],
    "vnc": ["network-edge-13", "policies-tem-01"], "rdp": ["identity-sec-08", "network-edge-13"],
    "db": ["network-edge-13", "data-managem-14"], "smbv1": ["patch-manage-01", "network-edge-13"],
    "snmp": ["network-edge-05"], "snmpdefault": ["network-edge-05"], "upnp": ["network-edge-05", "network-edge-12"],
    "tr069": ["network-edge-05", "network-edge-12"], "upnpdev": ["network-edge-06"],
    "adb": ["network-edge-06", "network-edge-10"], "localctl": ["network-edge-06", "network-edge-10"],
    "mqtt": ["network-edge-06"], "mqttopen": ["network-edge-06"], "rtsp": ["network-edge-06", "network-edge-02"],
    "ot": ["network-edge-02", "network-edge-10"], "flat": ["network-edge-10", "network-edge-06", "network-edge-02"],
    "httpclear": ["website-atta-09"], "certexp": ["website-atta-09"], "certself": ["website-atta-09"],
    "unknown": ["asset-manage-09", "asset-manage-10", "asset-manage-01"],
    "cvecrit": ["patch-manage-01", "endpoints-de-16", "patch-manage-03"],
    "cvehigh": ["patch-manage-01", "endpoints-de-16"], "cvemed": ["patch-manage-01", "endpoints-de-16"],
}


def _t(id, label, iot, kw, ports, dt):
    return {"id": id, "label": label, "iot": iot, "kw": kw, "ports": ports, "dt": dt}


TYPES = [
 _t("camera", "Camera / NVR", True, ["hikvision","dahua","axis communications","reolink","amcrest","uniview","wyze","arlo","lorex","swann","foscam","ip camera","ipcam","nvr","dvr","webcam","camera"], [554,8554,37777], ["webcam"]),
 _t("building", "Building / OT control", True, ["bacnet","modbus","tridium","niagara","johnson controls","schneider electric","distech","alerton","automated logic","hvac"], [502,47808], ["specialized","power-device"]),
 _t("printer", "Printer / copier", True, ["printer","laserjet","officejet","brother","canon","epson","xerox","lexmark","kyocera","ricoh","konica","jetdirect","mfc-"], [9100,515,631], ["printer","print server"]),
 _t("nas", "Storage / NAS", True, ["synology","qnap","diskstation","western digital","my cloud","readynas","terramaster","asustor","buffalo"], [], ["storage-misc"]),
 _t("voip", "VoIP phone", True, ["polycom","poly vvx","yealink","grandstream","cisco spa","snom","avaya","mitel","sip phone"], [5060], ["voip phone","voip adapter","pbx"]),
 _t("media", "TV / media", True, ["roku","chromecast","googlecast","apple tv","appletv","airtunes","vizio","lg electronics","webos","tizen","sonos","bravia","fire tv","tvbox","tv-box","android tv"], [8008,8009,7000,1400,8060], ["media device","game console"]),
 _t("smarthome", "Smart home / IoT", True, ["espressif","tuya","shelly","signify","philips lighting","hue bridge","ecobee","nest labs","google home","amazon technologies","echo","kasa","wemo","belkin","lifx","smartthings","thermostat","mqtt","iot"], [1883,8883,9999,6668], []),
 _t("network", "Router / switch / AP", False, ["router","ubiquiti","unifi","netgear","tp-link","cisco","aruba","meraki","mikrotik","fortinet","fortigate","sonicwall","firewalla","eero","linksys","juniper","pfsense","opnsense","routeros","gateway","access point"], [7547], ["router","wap","switch","firewall","broadband router","bridge","load balancer"]),
 _t("mobile", "Phone / tablet", False, ["iphone","ipad","android"], [62078], ["phone"]),
 _t("computer", "Computer / server", False, ["windows","microsoft","macos","mac os","os x","ubuntu","debian","centos","red hat","dell","lenovo","super micro","vmware"], [3389,135,139], ["general purpose"]),
]
UNKNOWN = _t("unknown", "Unidentified", True, [], [], [])

GRADE_TEXT = {
    "A": "Few weak points found. Keep scanning on a schedule to catch drift.",
    "B": "A small number of weak points. Most can be fixed in an afternoon.",
    "C": "Several weak points that an attacker on the network could use. Work through the top fixes.",
    "D": "Many devices have serious weak points. Prioritize the top fixes this month.",
    "F": "Serious, easy-to-exploit weak points are widespread. Start with the top fixes this week.",
}
