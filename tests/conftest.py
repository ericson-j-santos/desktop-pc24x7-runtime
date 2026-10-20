from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Production entry points execute from scripts/, so sibling modules are importable.
# Tests load those entry points via importlib, which does not add scripts/ to sys.path.
SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
scripts_path = str(SCRIPTS)
if scripts_path not in sys.path:
    sys.path.insert(0, scripts_path)


@pytest.fixture(autouse=True)
def isolate_broker_os_dependency(request, monkeypatch):
    """Confine broker platform mocks to its module, never the process-wide os."""
    module = getattr(request.module, "m", None)
    if getattr(module, "__file__", None) != str(SCRIPTS / "desktop_admin_broker.py"):
        yield
        return
    original_os = module.os
    original_name = original_os.name
    # Preserve native functions and the actual environment mapping. Rebinding
    # name/environ in a broker test now affects only this per-test namespace.
    monkeypatch.setattr(module, "os", SimpleNamespace(**vars(original_os)))
    yield
    assert original_os.name == original_name, "broker test leaked its platform mock"
