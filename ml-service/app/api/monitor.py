"""Live network monitor endpoints."""

from __future__ import annotations

import logging
from typing import List, Optional, Union

import psutil
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.live_monitor import live_monitor

router = APIRouter(prefix="/api/monitor", tags=["monitor"])
logger = logging.getLogger(__name__)


class StartRequest(BaseModel):
    # Accept a single interface name OR a list of interface names.
    # Single-string form kept for backward compat with existing clients.
    interface: Optional[str] = None
    interfaces: Optional[List[str]] = None

    def resolved_interfaces(self) -> List[str]:
        if self.interfaces:
            return self.interfaces
        if self.interface:
            return [self.interface]
        raise ValueError("Provide 'interface' or 'interfaces'")


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
        ifaces = req.resolved_interfaces()
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    try:
        return live_monitor.start(ifaces)
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


class IsolateRequest(BaseModel):
    ip: str
    reason: str = ""


@router.post("/isolate")
def isolate_ip(req: IsolateRequest):
    """Quarantine an IP on the entire LAN via ARP cache poisoning.

    Requires the live monitor to be running (it owns the network interface).
    The isolated host's traffic is intercepted by this machine and dropped,
    effectively cutting it off from the LAN — not just from this machine.
    """
    if not live_monitor.running:
        raise HTTPException(
            status_code=400,
            detail="Monitor must be running to isolate hosts — start capture first.",
        )
    newly_added = live_monitor.isolate_ip(req.ip, req.reason)
    return {"isolated": req.ip, "newly_added": newly_added, "status": "active"}


@router.delete("/isolate/{ip:path}")
def release_ip(ip: str):
    """Remove an IP from network isolation and restore ARP caches."""
    released = live_monitor.release_ip(ip)
    return {"released": ip, "was_isolated": released}


@router.get("/isolated")
def list_isolated():
    """Return the list of currently isolated IPs with their metadata."""
    return {"isolated": live_monitor.list_isolated()}


class AutostartRequest(BaseModel):
    interface: Optional[str] = None      # legacy single-interface form
    interfaces: Optional[List[str]] = None  # multi-interface form


@router.post("/autostart")
def set_autostart(req: AutostartRequest):
    """Persist the preferred capture interface(s) to .env so they survive restarts."""
    import json
    import re
    from pathlib import Path

    ifaces: List[str] = req.interfaces or ([req.interface] if req.interface else [])
    env_path = Path(__file__).resolve().parents[2] / ".env"
    env_path.touch(exist_ok=True)
    content = env_path.read_text()

    # Store as JSON array so multi-interface survives round-trips.
    key = "AUTOSTART_INTERFACE"
    value = json.dumps(ifaces[0] if len(ifaces) == 1 else ifaces)
    new_line = f"{key}={value}"
    if re.search(rf"^{key}=", content, re.MULTILINE):
        content = re.sub(rf"^{key}=.*$", new_line, content, flags=re.MULTILINE)
    else:
        content = content.rstrip("\n") + f"\n{new_line}\n"
    env_path.write_text(content)
    return {
        "saved": True,
        "interfaces": ifaces,
        "note": "Restart the ML service for auto-start to take effect.",
    }
