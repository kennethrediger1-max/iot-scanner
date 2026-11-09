"""Async nmap wrapper. Uses subprocess argv lists (no shell) and XML output on stdout."""
from __future__ import annotations

import asyncio
import ctypes
import os
import platform
import shutil
import subprocess

WIN_PATHS = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]

# Ports the default top-100 list misses but IoT gear commonly uses.
IOT_PORT_LIST = "1-1024,1883,8883,5555,8008,8009,8080,8443,8554,9100,9999,6668,37777,47808,502,7547"


class NmapError(Exception):
    """Carries a stable `code` the UI can switch on, plus a human message."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def find_nmap() -> str | None:
    path = shutil.which("nmap")
    if path:
        return path
    return next((p for p in WIN_PATHS if os.path.exists(p)), None)


def is_privileged() -> bool:
    """True for root (POSIX) or an elevated Administrator shell (Windows)."""
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return os.geteuid() == 0


def system_info() -> dict:
    path = find_nmap()
    version = None
    if path:
        try:
            out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10).stdout
            version = out.splitlines()[0] if out else None
        except Exception:
            pass
    return {"os": platform.system(), "nmap": {"installed": bool(path), "path": path, "version": version},
            "privileged": is_privileged()}


def _explain(stderr: str, rc: int) -> NmapError:
    """Translate common nmap failures into actionable messages."""
    low = stderr.lower()
    if "vulners" in low and any(k in low for k in ("did not match", "failed to initialize", "could not locate")):
        return NmapError("script_missing", "The vulners script was not found in your Nmap install. Reinstall Nmap, or turn off the vulnerability lookup.", 500)
    if "requires root" in low or "operation not permitted" in low or "permission denied" in low:
        return NmapError("needs_privileges", "This scan needs administrator rights. Restart the app with sudo (macOS/Linux) or from an Administrator terminal (Windows).", 403)
    if "npcap" in low or "winpcap" in low or "failed to open device" in low:
        return NmapError("npcap_missing", "Npcap is missing or not working. Reinstall Nmap and keep the Npcap option ticked, then run as Administrator.", 500)
    if "failed to resolve" in low or "no targets were specified" in low:
        return NmapError("bad_target", "Nmap could not use the target you gave.", 400)
    return NmapError("nmap_failed", f"Nmap exited with code {rc}: {stderr.strip()[:300] or 'no details'}", 500)


async def _run(args: list[str], timeout: int) -> str:
    path = find_nmap()
    if not path:
        raise NmapError("not_installed", "Nmap is not installed or not on PATH. Follow the install guide, then retry.", 503)
    proc = await asyncio.create_subprocess_exec(path, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise NmapError("timeout", f"The scan took longer than {timeout // 60} minutes and was stopped. Try fewer hosts.", 504) from None
    if proc.returncode != 0:
        raise _explain(err.decode(errors="replace"), proc.returncode)
    return out.decode(errors="replace")


async def ping_sweep(cidr: str) -> str:
    """Fast host discovery. With privileges nmap uses ARP, which also returns MAC addresses."""
    return await _run(["-sn", "-n", "-oX", "-", cidr], timeout=180)


async def iot_scan(targets: list[str], profile: str = "top100", cve: bool = True) -> str:
    """SYN scan + service/version + OS detection (+ CVE lookup via the vulners script). Needs root/Administrator.

    The vulners script sends detected software versions to vulners.com, so it needs internet access."""
    if not is_privileged():
        raise NmapError("needs_privileges", "Service and OS detection needs administrator rights. Restart the app with sudo (macOS/Linux) or from an Administrator terminal (Windows).", 403)
    ports = ["-p", IOT_PORT_LIST] if profile == "iot_extended" else ["--top-ports", "100"]
    args = ["-sS", "-sV", "-O", "--osscan-guess", "-Pn", "-n", "-T4", *ports,
            "--host-timeout", "8m" if cve else "4m", "--max-retries", "2",
            *(["--script", "vulners"] if cve else []), "-oX", "-", *targets]
    return await _run(args, timeout=1800)
