from __future__ import annotations
import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "pc24x7_host_policy.py"
SPEC = importlib.util.spec_from_file_location("pc24x7_host_policy_tested", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

def test_known_hosts_are_explicitly_authorized() -> None:
    assert set(m.authorized_hostnames()) == {"DESKTOP-PDQK954", "DESKTOP-RP23OGS", "NOTERI"}

@pytest.mark.parametrize("host", ["DESKTOP-PDQK954", "desktop-rp23ogs", "Noteri"])
def test_authorized_host_is_case_insensitive(host: str) -> None:
    assert m.authorized_host(host).runner_name.lower().endswith("-runtime")

def test_unknown_host_fails_closed() -> None:
    with pytest.raises(ValueError, match="host não autorizado"):
        m.authorized_host("UNKNOWN-PC")

def test_profiles_do_not_contain_secrets() -> None:
    source = MODULE.read_text(encoding="utf-8").lower()
    for forbidden in ("gh_token", "github_token", "password", "private_key"):
        assert forbidden not in source
