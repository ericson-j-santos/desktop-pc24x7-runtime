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
    "desktop-pdqk954": HostProfile("DESKTOP-PDQK954", "desktop-primary", "DESKTOP-PDQK954-runtime", "pc24x7,desktop-runtime,runtime-dev,desktop-pdqk954"),
    "desktop-rp23ogs": HostProfile("DESKTOP-RP23OGS", "desktop-secondary", "DESKTOP-RP23OGS-runtime", "pc24x7,desktop-runtime,runtime-dev,desktop-rp23ogs"),
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


# Closed DEV contract shared by the read-only probe and runner bootstrap.
# Host authorization for every existing Runtime path remains unchanged.
from types import MappingProxyType

ORCHESTRATOR_DEV_RUNNER_PROFILE = MappingProxyType({
    "target": "orchestrator-dev",
    "environment": "dev",
    "host": "DESKTOP-PDQK954",
    "repository": "ericson-j-santos/reqsys-engineering-orchestrator",
    "runner_name": "DESKTOP-PDQK954-orchestrator-dev",
    "directory": "EngineeringOrchestratorDEV",
})
ORCHESTRATOR_DEV_RUNNER_REQUIRED_LABELS = frozenset({
    "self-hosted", "Windows", "X64", "orchestrator-dev", "desktop-pdqk954",
})
ORCHESTRATOR_DEV_RUNNER_PACKAGE = MappingProxyType({
    "version": "2.338.2",
    "filename": "actions-runner-win-x64-2.338.2.zip",
    "url": "https://github.com/actions/runner/releases/download/v2.338.2/actions-runner-win-x64-2.338.2.zip",
    "sha256": "a1f17aa987fc8158bc7521d284912267a0d01b7c2c4684b33c86783b5e8221cc",
    "size": 104210683,
})


def orchestrator_dev_runner_profile(hostname: str | None = None):
    profile = authorized_host(hostname)
    if profile.hostname != ORCHESTRATOR_DEV_RUNNER_PROFILE["host"]:
        raise ValueError("orchestrator_runner_host_not_authorized")
    return ORCHESTRATOR_DEV_RUNNER_PROFILE
