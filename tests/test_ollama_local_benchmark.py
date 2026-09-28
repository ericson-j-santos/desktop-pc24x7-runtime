from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ollama_local_benchmark.py"


def load_module():
    spec = importlib.util.spec_from_file_location("ollama_local_benchmark", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parse_contexts_preserves_order_and_removes_duplicates() -> None:
    mod = load_module()
    assert mod.parse_contexts("8192,32768,64000,32768") == [8192, 32768, 64000]


def test_parse_contexts_rejects_non_positive_value() -> None:
    mod = load_module()
    try:
        mod.parse_contexts("8192,0")
    except ValueError as exc:
        assert str(exc) == "context_must_be_positive"
    else:
        raise AssertionError("expected ValueError")


def test_loaded_model_finds_exact_model() -> None:
    mod = load_module()
    item = mod.loaded_model(
        [{"name": "gemma4:26b-q8-code", "context_length": 65536}],
        "gemma4:26b-q8-code",
    )
    assert item is not None
    assert item["context_length"] == 65536


def test_direct_generate_requests_context_seed_and_temperature(monkeypatch) -> None:
    mod = load_module()
    captured: dict[str, object] = {}

    def fake_http_json(url, *, payload=None, timeout=120):
        captured["url"] = url
        captured["payload"] = payload
        captured["timeout"] = timeout
        return {
            "model": "gemma4:26b-q8-code",
            "response": "OLLAMA_LOCAL_OK",
            "eval_count": 2,
            "eval_duration": 1_000_000_000,
            "prompt_eval_count": 4,
            "prompt_eval_duration": 2_000_000_000,
        }

    monkeypatch.setattr(mod, "http_json", fake_http_json)
    result = mod.direct_generate(
        "gemma4:26b-q8-code",
        "prompt",
        10,
        64000,
        expected="OLLAMA_LOCAL_OK",
    )

    assert result.ok is True
    assert result.sentinel_ok is True
    assert result.eval_tokens_per_second == 2.0
    assert result.prompt_tokens_per_second == 2.0
    assert captured["url"] == "http://127.0.0.1:11434/api/generate"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["options"] == {"temperature": 0, "seed": 42, "num_ctx": 64000}


def test_tool_call_probe_requires_expected_function_and_argument(monkeypatch) -> None:
    mod = load_module()

    def fake_http_json(url, *, payload=None, timeout=120):
        assert url == "http://127.0.0.1:11434/api/chat"
        return {
            "message": {
                "tool_calls": [
                    {
                        "function": {
                            "name": "benchmark_echo",
                            "arguments": {"value": "OLLAMA_TOOL_OK"},
                        }
                    }
                ]
            }
        }

    monkeypatch.setattr(mod, "http_json", fake_http_json)
    result = mod.tool_call_probe("gemma4:26b-q8-code", 10, 64000)
    assert result["ok"] is True
    assert result["tool_calls_count"] == 1


def test_tool_call_probe_is_fail_closed_for_wrong_argument(monkeypatch) -> None:
    mod = load_module()

    def fake_http_json(url, *, payload=None, timeout=120):
        return {
            "message": {
                "tool_calls": [
                    {
                        "function": {
                            "name": "benchmark_echo",
                            "arguments": {"value": "WRONG"},
                        }
                    }
                ]
            }
        }

    monkeypatch.setattr(mod, "http_json", fake_http_json)
    result = mod.tool_call_probe("gemma4:26b-q8-code", 10, 64000)
    assert result["ok"] is False
