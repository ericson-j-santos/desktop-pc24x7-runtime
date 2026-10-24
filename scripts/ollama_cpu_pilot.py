#!/usr/bin/env python3
"""Read-only local Ollama inventory and bounded Qwen 7B CPU-first smoke.

No model pulls, network fallback, repository edits, shell or secrets.
The caller must use the governed session and Command Gateway on a host.
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from typing import Any

MODEL = "qwen2.5-coder:7b"
SENTINEL = "OLLAMA_CPU_PILOT_OK"
BASE = "http://127.0.0.1:11434"
MAX_RESPONSE_BYTES = 131072
CONTEXT_TOKENS = 2048


class PilotBlocked(RuntimeError):
    """Sanitized, stable reason code only."""


def http_json(path: str, *, payload: dict[str, Any] | None = None, timeout: int = 10) -> dict[str, Any]:
    if path not in {"/api/tags", "/api/generate", "/api/ps"}:
        raise PilotBlocked("endpoint_not_allowed")
    data = None if payload is None else json.dumps(payload, ensure_ascii=True).encode("utf-8")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method="GET" if data is None else "POST")
    # Ignore proxy environment even if the host has HTTP(S)_PROXY configured.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        raise PilotBlocked("ollama_unreachable") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise PilotBlocked("response_too_large")
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError):
        raise PilotBlocked("invalid_json") from None
    if not isinstance(decoded, dict):
        raise PilotBlocked("invalid_response_schema")
    return decoded


def installed_model() -> dict[str, Any] | None:
    models = http_json("/api/tags").get("models")
    if not isinstance(models, list):
        raise PilotBlocked("inventory_invalid")
    found = [item for item in models if isinstance(item, dict) and item.get("name") == MODEL]
    if not found:
        return None
    if len(found) != 1:
        raise PilotBlocked("inventory_ambiguous")
    item = found[0]
    size, digest, details = item.get("size"), item.get("digest"), item.get("details")
    if (type(size) is not int or size <= 0 or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(details, dict) or details.get("format") != "gguf"):
        raise PilotBlocked("local_weights_not_verified")
    return {"name": MODEL, "size_bytes": size, "digest": digest}


def smoke(model: dict[str, Any]) -> dict[str, Any]:
    generated = http_json(
        "/api/generate",
        payload={
            "model": MODEL,
            "prompt": f"Responda apenas com {SENTINEL}, sem explicacoes.",
            "stream": False,
            "keep_alive": "1m",
            "options": {"temperature": 0, "seed": 42, "num_ctx": CONTEXT_TOKENS, "num_predict": 32},
        },
        timeout=120,
    )
    if (generated.get("model") != MODEL or generated.get("done") is not True
            or not isinstance(generated.get("response"), str)
            or generated["response"].strip() != SENTINEL):
        raise PilotBlocked("inference_validation_failed")
    loaded = http_json("/api/ps").get("models")
    if not isinstance(loaded, list):
        raise PilotBlocked("loaded_models_invalid")
    active = [
        item for item in loaded
        if isinstance(item, dict) and item.get("name") == MODEL and item.get("digest") == model["digest"]
    ]
    if len(active) != 1:
        raise PilotBlocked("local_loaded_model_not_verified")
    context = active[0].get("context_length")
    if type(context) is not int or context < CONTEXT_TOKENS:
        raise PilotBlocked("context_not_verified")
    tokens, duration = generated.get("eval_count"), generated.get("eval_duration")
    if type(tokens) is not int or tokens <= 0 or type(duration) is not int or duration <= 0:
        raise PilotBlocked("inference_metrics_missing")
    vram_bytes = active[0].get("size_vram")
    return {
        "tokens_generated": tokens,
        "tokens_per_second": round(tokens * 1_000_000_000 / duration, 2),
        "observed_context": context,
        "vram_bytes": vram_bytes if type(vram_bytes) is int and vram_bytes >= 0 else None,
        "exact_response": True,
        "local_loaded_digest_verified": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("inventory", "smoke"), required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", args.correlation_id) is None:
        raise SystemExit("invalid_correlation_id")
    evidence: dict[str, Any] = {
        "mode": args.mode,
        "model": MODEL,
        "correlation_id": args.correlation_id,
        "ollama_endpoint": BASE,
        "model_pull_performed": False,
        "cloud_fallback_configured": False,
        "production_touched": False,
    }
    try:
        model = installed_model()
        if model is None:
            evidence.update(state="model_not_installed", ok=False)
            print(json.dumps(evidence, sort_keys=True))
            return 2
        evidence.update(
            model_digest_prefix=model["digest"][:12],
            model_size_bytes=model["size_bytes"],
        )
        if args.mode == "inventory":
            evidence.update(state="installed_weights_verified_inference_not_tested", ok=True)
        else:
            evidence.update(smoke(model))
            evidence.update(state="smoke_validated", ok=True)
    except PilotBlocked as exc:
        evidence.update(state=str(exc), ok=False)
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["ok"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
