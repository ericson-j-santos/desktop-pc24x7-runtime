#!/usr/bin/env python3
"""Contrato versionado de hosts autorizados do PC24x7 Runtime."""
from __future__ import annotations
import socket
from dataclasses import dataclass

@dataclass(frozen=True)
class HostProfile:
    hostname: str
    role: str
    runner_name: str
    runner_labels: str

_PROFILES = {
    "desktop-pdqk954": HostProfile("DESKTOP-PDQK954", "desktop-primary", "DESKTOP-PDQK954-runtime", "pc24x7,desktop-runtime,runtime-dev"),
    "desktop-rp23ogs": HostProfile("DESKTOP-RP23OGS", "desktop-secondary", "DESKTOP-RP23OGS-runtime", "pc24x7,desktop-runtime,runtime-dev"),
    "noteri": HostProfile("NOTERI", "notebook-control", "NOTERI-runtime", "pc24x7,noteri,reqsys-dev"),
}

def authorized_host(hostname: str | None = None) -> HostProfile:
    observed = (hostname or socket.gethostname()).strip()
    profile = _PROFILES.get(observed.casefold())
    if profile is None:
        raise ValueError(f"host não autorizado: {observed}")
    return profile

def authorized_hostnames() -> tuple[str, ...]:
    return tuple(p.hostname for p in _PROFILES.values())
