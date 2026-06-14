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
