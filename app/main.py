"""FastAPI entry point. Run: python -m uvicorn app.main:app  (with sudo / as Administrator for scans)."""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .core import nmap_runner as nm
from .core import roe
from .core.network import detect_subnet
from .core.parser import build_report, parse_xml

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="IoT Network Scanner")
JOBS: dict[str, dict] = {}  # in-memory job store; fine for a single-user local tool


# ---- error handling -------------------------------------------------------
@app.exception_handler(roe.RoEError)
async def _roe_err(_: Request, e: roe.RoEError):
    return JSONResponse({"code": "roe", "detail": str(e)}, status_code=403)


@app.exception_handler(nm.NmapError)
async def _nmap_err(_: Request, e: nm.NmapError):
    return JSONResponse({"code": e.code, "detail": e.message}, status_code=e.status)


def require_roe(x_roe_token: str | None = Header(default=None)) -> dict:
    """Dependency that locks an endpoint until the RoE token is valid."""
    return roe.verify_token(x_roe_token)


# ---- models ---------------------------------------------------------------
class Accept(BaseModel):
    acknowledged: list[str]
    phrase: str
    name: str


class DiscoverReq(BaseModel):
    cidr: str


class ScanReq(BaseModel):
    targets: list[str]
    profile: str = "top100"  # or "iot_extended"
    cve: bool = True         # look up known vulnerabilities (needs internet)


# ---- public endpoints (no RoE needed) ------------------------------------
@app.get("/api/system")
def system():
    return nm.system_info()


@app.get("/api/roe")
def get_roe():
    return {"version": roe.ROE_VERSION, "items": roe.ROE_ITEMS, "phrase": roe.CONFIRM_PHRASE}


@app.post("/api/roe/accept")
def accept_roe(body: Accept):
    return roe.issue_token(body.acknowledged, body.phrase, body.name)


# ---- gated endpoints ------------------------------------------------------
@app.get("/api/subnet", dependencies=[Depends(require_roe)])
def subnet():
    try:
        return detect_subnet()
    except RuntimeError as e:
        return JSONResponse({"code": "no_network", "detail": str(e)}, status_code=503)


def _start(kind: str, coro_fn) -> dict:
    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {"id": job_id, "kind": kind, "status": "running"}

    async def work():
        try:
            JOBS[job_id].update(status="done", result=await coro_fn())
        except nm.NmapError as e:
            JOBS[job_id].update(status="error", code=e.code, detail=e.message)
        except ValueError as e:
            JOBS[job_id].update(status="error", code="parse_failed", detail=str(e))
        except Exception as e:  # never leave a job stuck on "running"
            JOBS[job_id].update(status="error", code="internal", detail=f"Unexpected error: {e}")

    asyncio.create_task(work())
    return {"job_id": job_id}


@app.post("/api/discover", dependencies=[Depends(require_roe)])
async def discover(body: DiscoverReq):
    cidr = roe.validate_targets([body.cidr])[0]

    async def run():
        hosts = parse_xml(await nm.ping_sweep(cidr))
        return {"hosts": [{k: h[k] for k in ("ip", "mac", "vendor", "hostnames")} for h in hosts]}

    return _start("discover", run)


@app.post("/api/scan", dependencies=[Depends(require_roe)])
async def scan(body: ScanReq):
    targets = roe.validate_targets(body.targets)
    profile = body.profile if body.profile in ("top100", "iot_extended") else "top100"

    async def run():
        return build_report(parse_xml(await nm.iot_scan(targets, profile, body.cve)), cve_checked=body.cve)

    return _start("scan", run)


@app.get("/api/jobs/{job_id}", dependencies=[Depends(require_roe)])
def job(job_id: str):
    return JOBS.get(job_id) or JSONResponse({"code": "not_found", "detail": "Unknown job."}, status_code=404)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
