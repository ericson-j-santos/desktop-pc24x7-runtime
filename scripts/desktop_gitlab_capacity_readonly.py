#!/usr/bin/env python3
"""Amostra limitada da capacidade do Desktop para piloto GitLab, sem mutacoes.

Deve executar SOMENTE via Command Gateway risk=1, em sessao validada, no SHA
exato do runtime. Uma amostra nao autoriza registro de runner ou deploy.
Nao coleta usuarios, processos, interfaces de rede, segredos ou caminhos locais.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
import platform
import re
import shutil
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

HOST = "DESKTOP-PDQK954"
GIB = 1024 ** 3
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CORRELATION_RE = re.compile(r"^gitlab-capacity-[1-9][0-9]{4,19}-1$")


class CapacityError(ValueError):
    """Controlado: nao deve propagar dado de ambiente nem caminho local."""


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_ulong), ("high", ctypes.c_ulong)]


def _file_time(value: _FileTime) -> int:
    return (int(value.high) << 32) | int(value.low)


def windows_cpu_ticks() -> tuple[int, int] | None:
    """Retorna total e idle acumulados (GetSystemTimes), sem subprocesso."""
    try:
        idle, kernel, user = _FileTime(), _FileTime(), _FileTime()
        fn = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemTimes
        fn.argtypes = [ctypes.POINTER(_FileTime)] * 3
        fn.restype = ctypes.c_int
        if not fn(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            return None
        return _file_time(kernel) + _file_time(user), _file_time(idle)
    except (AttributeError, OSError, ValueError):
        return None


def sample_cpu_percent(
    seconds: float,
    *,
    reader: Callable[[], tuple[int, int] | None] = windows_cpu_ticks,
    sleeper: Callable[[float], None] = time.sleep,
) -> float | None:
    if not (0.2 <= seconds <= 5.0 and math.isfinite(seconds)):
        raise CapacityError("sample_window_invalid")
    first = reader()
    if first is None:
        return None
    sleeper(seconds)
    second = reader()
    if second is None:
        return None
    total = second[0] - first[0]
    idle = second[1] - first[1]
    if total <= 0 or not 0 <= idle <= total:
        return None
    result = 100.0 * (total - idle) / total
    return round(result, 2) if math.isfinite(result) else None


class _MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ulong),
        ("load", ctypes.c_ulong),
        ("total_physical", ctypes.c_ulonglong),
        ("available_physical", ctypes.c_ulonglong),
        ("total_page", ctypes.c_ulonglong),
        ("available_page", ctypes.c_ulonglong),
        ("total_virtual", ctypes.c_ulonglong),
        ("available_virtual", ctypes.c_ulonglong),
        ("available_extended", ctypes.c_ulonglong),
    ]


def windows_memory_bytes() -> tuple[int, int] | None:
    try:
        value = _MemoryStatus()
        value.length = ctypes.sizeof(value)
        fn = ctypes.WinDLL("kernel32", use_last_error=True).GlobalMemoryStatusEx
        fn.argtypes = [ctypes.POINTER(_MemoryStatus)]
        fn.restype = ctypes.c_int
        if not fn(ctypes.byref(value)):
            return None
        total, available = int(value.total_physical), int(value.available_physical)
        if total <= 0 or not 0 <= available <= total:
            return None
        return total, available
    except (AttributeError, OSError, ValueError):
        return None


def system_disk_bytes() -> tuple[int, int] | None:
    """Somente o volume do Python em execucao; sem enumerar unidades alheias."""
    try:
        root = Path(sys.executable).anchor
        if not root:
            return None
        usage = shutil.disk_usage(root)
        total, free = int(usage.total), int(usage.free)
        if total <= 0 or not 0 <= free <= total:
            return None
        return total, free
    except (OSError, ValueError):
        return None


def collect(
    *,
    source_sha: str,
    correlation_id: str,
    sample_seconds: float = 0.5,
    hostname: Callable[[], str] = socket.gethostname,
    system: Callable[[], str] = platform.system,
    cpu: Callable[[float], float | None] = sample_cpu_percent,
    memory: Callable[[], tuple[int, int] | None] = windows_memory_bytes,
    disk: Callable[[], tuple[int, int] | None] = system_disk_bytes,
    cpus: Callable[[], int | None] = os.cpu_count,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict:
    if not SHA_RE.fullmatch(source_sha):
        raise CapacityError("source_sha_invalid")
    if not CORRELATION_RE.fullmatch(correlation_id):
        raise CapacityError("correlation_invalid")
    if hostname().upper() != HOST or system() != "Windows":
        raise CapacityError("host_or_os_rejected")
    if not (0.2 <= sample_seconds <= 5.0 and math.isfinite(sample_seconds)):
        raise CapacityError("sample_window_invalid")

    mem = memory()
    volume = disk()
    load = cpu(sample_seconds)
    cores = cpus()
    good_mem = (
        mem is not None and len(mem) == 2 and mem[0] > 0 and 0 <= mem[1] <= mem[0]
    )
    good_disk = (
        volume is not None and len(volume) == 2 and volume[0] > 0
        and 0 <= volume[1] <= volume[0]
    )
    valid = (
        isinstance(cores, int) and not isinstance(cores, bool) and cores > 0
        and load is not None and isinstance(load, (int, float))
        and math.isfinite(load) and 0 <= load <= 100
        and good_mem and good_disk
    )

    def gib(value: int) -> float:
        return round(value / GIB, 2)

    captured = clock()
    if captured.tzinfo is None:
        raise CapacityError("timestamp_not_utc")
    captured = captured.astimezone(timezone.utc)
    return {
        "schema_version": 1,
        "type": "desktop_gitlab_capacity_sample",
        "host": HOST,
        "os": "Windows",
        "correlation_id": correlation_id,
        "source_sha_claim": source_sha,
        "source_sha_must_be_validated_by_gateway": True,
        "captured_at_utc": captured.isoformat(),
        "sample_seconds": sample_seconds,
        "logical_cpus": cores if isinstance(cores, int) and not isinstance(cores, bool) and cores > 0 else None,
        "cpu_usage_percent": float(load) if isinstance(load, (int, float)) and math.isfinite(load) else None,
        "memory_total_gib": gib(mem[0]) if good_mem else None,
        "memory_available_gib": gib(mem[1]) if good_mem else None,
        "disk_total_gib": gib(volume[0]) if good_disk else None,
        "disk_free_gib": gib(volume[1]) if good_disk else None,
        "capacity_sample_complete": bool(valid),
        "ready_for_gitlab_runner": False,
        "reason": "single_sample_no_isolation_or_cost_attestation",
        "configuration_changed": False,
        "secrets_accessed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventario limitado Desktop; somente leitura")
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--sample-seconds", type=float, default=0.5)
    args = parser.parse_args()
    try:
        receipt = collect(
            source_sha=args.source_sha,
            correlation_id=args.correlation_id,
            sample_seconds=args.sample_seconds,
        )
    except (CapacityError, OSError, TypeError, ValueError) as error:
        # Nunca divulgar mensagem de excecao original nem caminhos/ambiente.
        print(json.dumps({"status": "blocked", "reason": type(error).__name__}))
        return 2
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=False, allow_nan=False))
    return 0 if receipt["capacity_sample_complete"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
