from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ollama_local_benchmark.py"


def load_module():
    spec = importlib.util.spec_from_file_location("ollama_local_benchmark", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_context_gate_accepts_64k_or_more() -> None:
    mod = load_module()
    ok, observed = mod.context_gate(
        [{"name": "gemma4:26b-q8-code", "context_length": 65536}],
        "gemma4:26b-q8-code",
        64000,
    )
    assert ok is True
    assert observed == 65536


def test_context_gate_rejects_32k_negative_control() -> None:
    mod = load_module()
    ok, observed = mod.context_gate(
        [{"name": "gemma4:26b-q8-code", "context_length": 32768}],
        "gemma4:26b-q8-code",
        64000,
    )
    assert ok is False
    assert observed == 32768


def test_context_gate_rejects_missing_model() -> None:
    mod = load_module()
    ok, observed = mod.context_gate([], "gemma4:26b-q8-code", 64000)
    assert ok is False
    assert observed is None


def test_direct_generate_requests_minimum_context(monkeypatch) -> None:
    mod = load_module()
    captured: dict[str, object] = {}

    def fake_http_json(url, *, payload=None, timeout=120):
        captured["url"] = url
        captured["payload"] = payload
        captured["timeout"] = timeout
        return {
            "model": "gemma4:26b-q8-code",
            "response": "OLLAMA_LOCAL_OK",
            "eval_count": 1,
            "eval_duration": 1_000_000_000,
        }

    monkeypatch.setattr(mod, "http_json", fake_http_json)
    result = mod.direct_generate(
        "gemma4:26b-q8-code",
        "OLLAMA_LOCAL_OK",
        10,
        64000,
    )

    assert result.ok is True
    assert captured["url"] == "http://127.0.0.1:11434/api/generate"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["options"]["num_ctx"] == 64000
