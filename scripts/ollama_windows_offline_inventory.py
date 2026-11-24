#!/usr/bin/env python3
"""Inventário offline, estrito e sem execução do Ollama/Qwen7B no RP23OGS (DEV).

Somente verifica caminhos de instalação e modelo padrão. Não inicia processo,
não percorre diretórios, não acessa a rede, não modifica arquivos e não declara
assinatura Authenticode ou integridade de pesos a partir da mera presença.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
import sys
from pathlib import Path
from typing import Any

HOST = "DESKTOP-RP23OGS"
MODEL = "qwen2.5-coder:7b"
SHA = re.compile(r"sha256:([0-9a-f]{64})\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._-]{8,100}\Z")
MAX_BINARY = 128 * 1024 * 1024
MAX_MANIFEST = 65536
MAX_LAYERS = 32
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class InventoryBlocked(RuntimeError):
    """Recusa sem detalhes sensíveis de filesystem."""


def _parts_safe(path: Path) -> None:
    if not path.is_absolute() or any(p in (".", "..") for p in path.parts):
        raise InventoryBlocked("untrusted_path")
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise InventoryBlocked("path_unreadable") from None
        if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0) & REPARSE_POINT):
            raise InventoryBlocked("reparse_path_rejected")


def _regular(path: Path, limit: int) -> os.stat_result | None:
    _parts_safe(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise InventoryBlocked("file_unreadable") from None
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise InventoryBlocked("file_kind_or_size_rejected")
    return info


def _stable(path: Path, info: os.stat_result) -> None:
    other = _regular(path, max(info.st_size, 1))
    if other is None or (other.st_dev, other.st_ino, other.st_size, other.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
        raise InventoryBlocked("file_changed_during_inventory")


def _hash_exe(path: Path) -> dict[str, Any]:
    before = _regular(path, MAX_BINARY)
    if before is None:
        return {"state": "missing"}
    digest = hashlib.sha256()
    first = b""
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            if not first:
                first = chunk[:4096]
            digest.update(chunk)
    _stable(path, before)
    if len(first) < 64 or first[:2] != b"MZ":
        raise InventoryBlocked("not_pe_executable")
    pos = int.from_bytes(first[0x3C:0x40], "little")
    if pos + 4 > len(first) or first[pos:pos + 4] != b"PE\x00\x00":
        raise InventoryBlocked("not_pe_executable")
    return {"state": "present_sha256_attested", "sha256": digest.hexdigest(),
            "size_bytes": before.st_size, "authenticode_verified": False}


def _manifest(path: Path) -> dict[str, Any] | None:
    before = _regular(path, MAX_MANIFEST)
    if before is None:
        return None
    with path.open("rb") as handle:
        raw = handle.read(MAX_MANIFEST + 1)
    _stable(path, before)
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeError):
        raise InventoryBlocked("invalid_model_manifest") from None
    if type(parsed) is not dict or parsed.get("schemaVersion") != 2:
        raise InventoryBlocked("invalid_model_manifest")
    layers = parsed.get("layers")
    config = parsed.get("config")
    if type(layers) is not list or not 1 <= len(layers) <= MAX_LAYERS or type(config) is not dict:
        raise InventoryBlocked("invalid_model_manifest")
    return {"raw_sha256": hashlib.sha256(raw).hexdigest(), "descriptors": [config, *layers]}


def _model(models_root: Path) -> dict[str, Any]:
    manifest = models_root / "manifests" / "registry.ollama.ai" / "library" / "qwen2.5-coder" / "7b"
    parsed = _manifest(manifest)
    if parsed is None:
        return {"state": "standard_manifest_missing", "weights_integrity_verified": False}
    seen: set[str] = set()
    count = 0
    for obj in parsed["descriptors"]:
        if type(obj) is not dict or type(obj.get("size")) is not int or obj["size"] <= 0:
            raise InventoryBlocked("invalid_model_descriptor")
        raw_digest = obj.get("digest")
        match = SHA.fullmatch(raw_digest) if type(raw_digest) is str else None
        if match is None or raw_digest in seen:
            raise InventoryBlocked("invalid_model_descriptor")
        seen.add(raw_digest)
        blob = models_root / "blobs" / ("sha256-" + match.group(1))
        info = _regular(blob, max(obj["size"], 1))
        if info is None or info.st_size != obj["size"]:
            return {"state": "layer_missing_or_size_mismatch", "weights_integrity_verified": False}
        count += 1
    return {"state": "standard_manifest_and_layers_present", "manifest_sha256": parsed["raw_sha256"],
            "descriptors_checked": count, "weights_integrity_verified": False}


def collect(*, host: str, platform: str, localappdata: Path, userprofile: Path,
            programfiles: Path | None) -> dict[str, Any]:
    if host.upper() != HOST or platform != "win32":
        raise InventoryBlocked("host_or_platform_rejected")
    if localappdata != userprofile / "AppData" / "Local":
        raise InventoryBlocked("profile_location_rejected")
    options = [("user_programs", localappdata / "Programs" / "Ollama" / "ollama.exe"),
               ("user_local", localappdata / "Ollama" / "ollama.exe")]
    if programfiles is not None:
        options.append(("machine_programs", programfiles / "Ollama" / "ollama.exe"))
    candidates = []
    for label, path in options:
        inspected = _hash_exe(path)
        candidates.append({"candidate": label, "path": str(path), **inspected})
    model = _model(userprofile / ".ollama" / "models")
    return {"result": "OLLAMA_WINDOWS_OFFLINE_INVENTORY", "host": HOST,
            "model": MODEL, "binary_candidates": candidates, "standard_model": model,
            "binary_executed": False, "model_loaded": False, "model_calls": 0,
            "model_pull_performed": False, "network_used": False, "host_mutated": False,
            "alternate_model_locations_checked": False, "launch_authorized": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    if CORRELATION.fullmatch(args.correlation_id) is None:
        raise SystemExit("invalid_correlation_id")
    try:
        local = os.environ.get("LOCALAPPDATA", "")
        profile = os.environ.get("USERPROFILE", "")
        if not local or not profile:
            raise InventoryBlocked("profile_env_missing")
        evidence = collect(host=socket.gethostname(), platform=sys.platform,
                           localappdata=Path(local), userprofile=Path(profile),
                           programfiles=Path(os.environ["PROGRAMFILES"]) if os.environ.get("PROGRAMFILES") else None)
        evidence["correlation_id"] = args.correlation_id
        print(json.dumps(evidence, sort_keys=True))
        return 0
    except InventoryBlocked as exc:
        print(json.dumps({"result": "OLLAMA_WINDOWS_OFFLINE_INVENTORY_BLOCKED",
                          "correlation_id": args.correlation_id, "reason_code": str(exc),
                          "host_mutated": False, "model_calls": 0}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
