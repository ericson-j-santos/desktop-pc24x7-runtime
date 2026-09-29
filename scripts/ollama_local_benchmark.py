#!/usr/bin/env python3
"""Benchmark reproduzível e somente leitura do Ollama local no Desktop PC24x7."""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class CallResult:
    ok: bool
    latency_ms: int
    model: str | None
    response: str
    sentinel_ok: bool
    eval_count: int | None = None
    eval_tokens_per_second: float | None = None
    prompt_eval_count: int | None = None
    prompt_tokens_per_second: float | None = None
    fallback_used: bool | None = None
    error: str | None = None


def http_json(url: str, *, payload: dict[str, Any] | None = None, timeout: int = 120) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    method = "GET"
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"http_{exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(type(exc).__name__) from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("invalid_json") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("invalid_payload")
    return parsed


def rate(count: Any, duration_ns: Any) -> float | None:
    if isinstance(count, int) and isinstance(duration_ns, int) and duration_ns > 0:
        return round(count / (duration_ns / 1_000_000_000), 2)
    return None


def parse_contexts(raw: str) -> list[int]:
    values: list[int] = []
    for part in raw.split(","):
        value = int(part.strip())
        if value <= 0:
            raise ValueError("context_must_be_positive")
        if value not in values:
            values.append(value)
    if not values:
        raise ValueError("contexts_required")
    return values


def list_models() -> list[dict[str, Any]]:
    data = http_json("http://127.0.0.1:11434/api/tags", timeout=15)
    items = data.get("models")
    if not isinstance(items, list):
        return []
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        details = item.get("details") or {}
        result.append(
            {
                "name": str(item.get("name") or ""),
                "size_bytes": int(item.get("size") or 0),
                "parameter_size": str(details.get("parameter_size") or ""),
                "quantization_level": str(details.get("quantization_level") or ""),
            }
        )
    return result


def loaded_models() -> list[dict[str, Any]]:
    data = http_json("http://127.0.0.1:11434/api/ps", timeout=15)
    items = data.get("models")
    if not isinstance(items, list):
        return []
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "name": str(item.get("name") or ""),
                "size_bytes": int(item.get("size") or 0),
                "size_vram_bytes": int(item.get("size_vram") or 0),
                "context_length": int(item.get("context_length") or 0),
            }
        )
    return result


def loaded_model(loaded: list[dict[str, Any]], model: str) -> dict[str, Any] | None:
    return next((item for item in loaded if item.get("name") == model), None)


def direct_generate(
    model: str,
    prompt: str,
    timeout: int,
    num_ctx: int,
    *,
    expected: str | None = None,
    json_format: bool = False,
) -> CallResult:
    started = time.perf_counter()
    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "5m",
        "options": {"temperature": 0, "seed": 42, "num_ctx": num_ctx},
    }
    if json_format:
        payload["format"] = "json"
    try:
        data = http_json("http://127.0.0.1:11434/api/generate", payload=payload, timeout=timeout)
        response = str(data.get("response") or "").strip()
        return CallResult(
            ok=bool(response),
            latency_ms=int((time.perf_counter() - started) * 1000),
            model=str(data.get("model") or model),
            response=response,
            sentinel_ok=True if expected is None else expected in response,
            eval_count=data.get("eval_count") if isinstance(data.get("eval_count"), int) else None,
            eval_tokens_per_second=rate(data.get("eval_count"), data.get("eval_duration")),
            prompt_eval_count=(
                data.get("prompt_eval_count")
                if isinstance(data.get("prompt_eval_count"), int)
                else None
            ),
            prompt_tokens_per_second=rate(
                data.get("prompt_eval_count"), data.get("prompt_eval_duration")
            ),
        )
    except RuntimeError as exc:
        return CallResult(
            ok=False,
            latency_ms=int((time.perf_counter() - started) * 1000),
            model=None,
            response="",
            sentinel_ok=False,
            error=str(exc),
        )


def gateway_generate(model: str, sentinel: str, timeout: int, correlation_id: str) -> CallResult:
    started = time.perf_counter()
    try:
        data = http_json(
            "http://127.0.0.1:8008/v1/chat",
            payload={
                "model": model,
                "fallback_model": model,
                "task_type": "chat",
                "prompt": f"Responda somente com {sentinel}. Sem explicação.",
                "contexto": "",
                "entrada": "",
                "correlation_id": correlation_id,
                "source": "pc24x7-local-benchmark",
            },
            timeout=timeout,
        )
        response = str(data.get("response") or "").strip()
        return CallResult(
            ok=bool(response),
            latency_ms=int((time.perf_counter() - started) * 1000),
            model=str(data.get("model") or "") or None,
            response=response,
            sentinel_ok=sentinel in response,
            fallback_used=bool(data.get("fallback_used", False)),
        )
    except RuntimeError as exc:
        return CallResult(
            ok=False,
            latency_ms=int((time.perf_counter() - started) * 1000),
            model=None,
            response="",
            sentinel_ok=False,
            error=str(exc),
        )


def tool_call_probe(model: str, timeout: int, num_ctx: int) -> dict[str, Any]:
    sentinel = "OLLAMA_TOOL_OK"
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {
                "role": "user",
                "content": (
                    "Use obrigatoriamente a ferramenta benchmark_echo uma vez, "
                    f"passando value={sentinel}. Não responda com texto comum."
                ),
            }
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "benchmark_echo",
                    "description": "Retorna um valor para validar tool-calling.",
                    "parameters": {
                        "type": "object",
                        "properties": {"value": {"type": "string"}},
                        "required": ["value"],
                    },
                },
            }
        ],
        "options": {"temperature": 0, "seed": 42, "num_ctx": num_ctx},
    }
    started = time.perf_counter()
    try:
        data = http_json("http://127.0.0.1:11434/api/chat", payload=payload, timeout=timeout)
        message = data.get("message") if isinstance(data.get("message"), dict) else {}
        calls = message.get("tool_calls") if isinstance(message, dict) else []
        matched = False
        if isinstance(calls, list):
            for call in calls:
                function = call.get("function") if isinstance(call, dict) else None
                if not isinstance(function, dict) or function.get("name") != "benchmark_echo":
                    continue
                arguments = function.get("arguments")
                if isinstance(arguments, dict) and arguments.get("value") == sentinel:
                    matched = True
        return {
            "ok": matched,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "tool_calls_count": len(calls) if isinstance(calls, list) else 0,
            "sentinel_ok": matched,
        }
    except RuntimeError as exc:
        return {
            "ok": False,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "tool_calls_count": 0,
            "sentinel_ok": False,
            "error": str(exc),
        }


def structured_quality_probe(model: str, timeout: int, num_ctx: int) -> dict[str, Any]:
    result = direct_generate(
        model,
        (
            'Dados: nome="Ana"; prioridade=7. '
            'Responda somente JSON com as chaves nome e prioridade, preservando os valores.'
        ),
        timeout,
        num_ctx,
        json_format=True,
    )
    parsed: dict[str, Any] | None = None
    try:
        value = json.loads(result.response)
        if isinstance(value, dict):
            parsed = value
    except json.JSONDecodeError:
        parsed = None
    ok = bool(parsed and parsed.get("nome") == "Ana" and parsed.get("prioridade") == 7)
    return {"ok": ok, "call": asdict(result), "parsed": parsed}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="gemma4:26b-q8-code")
    parser.add_argument("--timeout", type=int, default=150)
    parser.add_argument("--contexts", default="8192,32768,64000")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args()

    contexts = parse_contexts(args.contexts)
    if args.repetitions < 2 or args.repetitions > 10:
        raise SystemExit("repetitions_must_be_between_2_and_10")
    max_context = max(contexts)
    sentinel = "OLLAMA_LOCAL_OK"
    evidence: dict[str, Any] = {
        "benchmark_version": 2,
        "correlation_id": args.correlation_id,
        "requested_model": args.model,
        "contexts": contexts,
        "repetitions": args.repetitions,
        "direct_endpoint": "127.0.0.1:11434",
        "gateway_endpoint": "127.0.0.1:8008",
        "cloud_called": False,
        "model_pull_performed": False,
        "secrets_read": False,
        "production_touched": False,
    }

    try:
        models = list_models()
    except RuntimeError as exc:
        evidence.update({"ok": False, "state": "ollama_unreachable", "error": str(exc)})
        print(json.dumps(evidence, ensure_ascii=True, sort_keys=True))
        return 3

    evidence["installed_models"] = models
    if args.model not in {item["name"] for item in models}:
        evidence.update({"ok": False, "state": "requested_model_not_installed"})
        print(json.dumps(evidence, ensure_ascii=True, sort_keys=True))
        return 4

    context_results = []
    first_max_call: CallResult | None = None
    for requested in contexts:
        call = direct_generate(
            args.model,
            f"Responda somente com {sentinel}. Sem explicação.",
            args.timeout,
            requested,
            expected=sentinel,
        )
        if requested == max_context:
            first_max_call = call
        observed = None
        size_bytes = None
        size_vram_bytes = None
        try:
            item = loaded_model(loaded_models(), args.model)
            if item:
                observed = int(item.get("context_length") or 0)
                size_bytes = int(item.get("size_bytes") or 0)
                size_vram_bytes = int(item.get("size_vram_bytes") or 0)
        except RuntimeError:
            pass
        context_results.append(
            {
                "requested_context": requested,
                "observed_context": observed,
                "context_ok": bool(observed is not None and observed >= requested),
                "size_bytes": size_bytes,
                "size_vram_bytes": size_vram_bytes,
                "call": asdict(call),
            }
        )
    evidence["context_ladder"] = context_results

    repeat_calls: list[CallResult] = []
    if first_max_call is not None:
        repeat_calls.append(first_max_call)
    while len(repeat_calls) < args.repetitions:
        repeat_calls.append(
            direct_generate(
                args.model,
                f"Responda somente com {sentinel}. Sem explicação.",
                args.timeout,
                max_context,
                expected=sentinel,
            )
        )
    repeatability_ok = all(
        item.ok and item.sentinel_ok and item.response == repeat_calls[0].response
        for item in repeat_calls
    )
    evidence["repeatability"] = {
        "ok": repeatability_ok,
        "distinct_responses": len({item.response for item in repeat_calls}),
        "runs": [asdict(item) for item in repeat_calls],
    }

    quality = structured_quality_probe(args.model, args.timeout, max_context)
    evidence["structured_quality"] = quality

    tool_call = tool_call_probe(args.model, args.timeout, max_context)
    evidence["tool_calling"] = tool_call

    gateway = gateway_generate(args.model, sentinel, args.timeout, args.correlation_id)
    evidence["gateway"] = asdict(gateway)

    context_ok = all(item["context_ok"] and item["call"]["sentinel_ok"] for item in context_results)
    evidence["ok"] = bool(
        context_ok
        and repeatability_ok
        and quality["ok"]
        and tool_call["ok"]
        and gateway.ok
        and gateway.sentinel_ok
        and gateway.model == args.model
        and gateway.fallback_used is False
    )
    evidence["state"] = "validated" if evidence["ok"] else "validation_failed"
    print(json.dumps(evidence, ensure_ascii=True, sort_keys=True))
    return 0 if evidence["ok"] else 5


if __name__ == "__main__":
    raise SystemExit(main())
