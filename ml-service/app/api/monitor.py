"""Live network monitor endpoints."""

from __future__ import annotations

import logging
from typing import List, Optional

import psutil
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.live_monitor import live_monitor

router = APIRouter(prefix="/api/monitor", tags=["monitor"])
logger = logging.getLogger(__name__)


class StartRequest(BaseModel):
    interface: str


class InterfaceInfo(BaseModel):
    name: str
    is_up: bool
    speed_mbps: Optional[int] = None
    addresses: List[str] = []


@router.get("/interfaces", response_model=List[InterfaceInfo])
def list_interfaces():
    """Return all non-loopback network interfaces available for capture."""
    result: List[InterfaceInfo] = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for name, s in stats.items():
        if name == "lo" or name.startswith(("docker", "veth", "br-")):
            continue
        ip_list = []
        for a in addrs.get(name, []):
            if a.family.name in ("AF_INET", "AF_INET6") and a.address:
                ip_list.append(a.address)
        result.append(
            InterfaceInfo(
                name=name,
                is_up=s.isup,
                speed_mbps=(s.speed if s.speed > 0 else None),
                addresses=ip_list,
            )
        )
    return result


@router.post("/start")
def start_monitor(req: StartRequest):
    if live_monitor.running:
        return live_monitor.status()
    try:
        return live_monitor.start(req.interface)
    except Exception as e:
        logger.exception("Failed to start monitor")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
def stop_monitor():
    return live_monitor.stop()


@router.get("/status")
def status():
    return live_monitor.status()


@router.post("/drain")
def drain(limit: int = 200):
    """Pop and return pending non-Benign detections (called by the Java backend)."""
    return {"detections": live_monitor.drain_detections(limit=limit)}


class AutostartRequest(BaseModel):
    interface: str  # empty string to disable


@router.post("/autostart")
def set_autostart(req: AutostartRequest):
    """Persist the preferred capture interface to .env so it survives restarts."""
    import re
    from pathlib import Path
    env_path = Path(__file__).resolve().parents[2] / ".env"
    env_path.touch(exist_ok=True)
    content = env_path.read_text()
    key = "AUTOSTART_INTERFACE"
    new_line = f'{key}="{req.interface}"'
    if re.search(rf"^{key}=", content, re.MULTILINE):
        content = re.sub(rf"^{key}=.*$", new_line, content, flags=re.MULTILINE)
    else:
        content = content.rstrip("\n") + f"\n{new_line}\n"
    env_path.write_text(content)
    return {"saved": True, "interface": req.interface,
            "note": "Restart the ML service for auto-start to take effect."}
