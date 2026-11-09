"""Rules of Engagement (RoE) gate.

The scanning endpoints are locked until the user acknowledges every RoE item AND
types a confirmation phrase. A successful acceptance returns a short-lived,
HMAC-signed token that every scan request must carry (X-RoE-Token header).
The signing key is random per server start, so tokens never survive a restart.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import time

ROE_VERSION = "1.0"
CONFIRM_PHRASE = "I AUTHORIZE THIS SCAN"
TOKEN_TTL_SECONDS = 3600
MAX_TARGETS = 1024  # hard cap on addresses per request

ROE_ITEMS = [
    {"id": "own", "text": "I own this network, or I have explicit written permission from the owner to scan it."},
    {"id": "scope", "text": "I will only scan private (RFC 1918) addresses on the network I am connected to."},
    {"id": "impact", "text": "I understand scans can slow down or crash fragile devices such as old cameras, printers and controllers."},
    {"id": "liability", "text": "I accept responsibility for how I use this tool and for any consequences of scanning."},
]

_SECRET = secrets.token_bytes(32)


class RoEError(Exception):
    """Raised when RoE acceptance or a token check fails. Maps to HTTP 403."""


def _sign(payload: bytes) -> str:
    return hmac.new(_SECRET, payload, hashlib.sha256).hexdigest()


def issue_token(acknowledged: list[str], phrase: str, name: str) -> dict:
    """Validate the acceptance form and return a signed token."""
    missing = {i["id"] for i in ROE_ITEMS} - set(acknowledged)
    if missing:
        raise RoEError(f"Every item must be acknowledged. Missing: {', '.join(sorted(missing))}.")
    if phrase.strip().upper() != CONFIRM_PHRASE:
        raise RoEError(f'Type the phrase exactly: "{CONFIRM_PHRASE}".')
    if len(name.strip()) < 2:
        raise RoEError("Enter your name so the acceptance can be logged.")
    body = json.dumps({"v": ROE_VERSION, "n": name.strip()[:80], "exp": int(time.time()) + TOKEN_TTL_SECONDS}).encode()
    token = base64.urlsafe_b64encode(body).decode() + "." + _sign(body)
    return {"token": token, "expires_in": TOKEN_TTL_SECONDS}


def verify_token(token: str | None) -> dict:
    """Return the token payload or raise RoEError."""
    if not token or "." not in token:
        raise RoEError("Rules of Engagement not accepted. Accept them to unlock scanning.")
    b64, sig = token.rsplit(".", 1)
    try:
        body = base64.urlsafe_b64decode(b64.encode())
        payload = json.loads(body)
    except Exception:
        raise RoEError("Invalid RoE token.") from None
    if not hmac.compare_digest(sig, _sign(body)):
        raise RoEError("Invalid RoE token.")
    if payload.get("exp", 0) < time.time() or payload.get("v") != ROE_VERSION:
        raise RoEError("RoE acceptance expired. Accept the Rules of Engagement again.")
    return payload


def validate_targets(targets: list[str]) -> list[str]:
    """Allow only private IPv4 hosts/networks, capped in size. Returns normalized strings.

    Targets are passed to nmap as separate argv items (never through a shell), and
    only values that parse as IPs/CIDRs get here, so option injection is impossible.
    """
    if not targets:
        raise RoEError("No targets given.")
    total, out = 0, []
    for raw in targets:
        try:
            net = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError:
            raise RoEError(f"'{raw}' is not a valid IP address or CIDR range.") from None
        if net.version != 4 or not net.is_private or net.is_loopback or net.is_link_local:
            raise RoEError(f"{raw} is outside the allowed private ranges (10/8, 172.16/12, 192.168/16).")
        total += net.num_addresses
        if total > MAX_TARGETS:
            raise RoEError(f"Too many addresses (limit {MAX_TARGETS}). Scan a smaller range.")
        out.append(str(net.network_address) if net.prefixlen == 32 else str(net))
    return out
