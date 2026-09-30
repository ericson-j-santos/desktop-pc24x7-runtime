from pathlib import Path

from scripts import desktop_stable_bootstrap_executor as subject


def test_executor_contract_is_fixed_to_confirmed_desktop_file() -> None:
    assert subject.EXPECTED_HOST == "DESKTOP-PDQK954"
    assert subject.SCRIPT_PATH == Path(
        r"C:\dev\chatgpt-workers\reqsys-orchestrator-24x7-runtime\scripts\Activate-Desktop-Stable-Bootstrap.ps1"
    )
    assert (
        subject.EXPECTED_SHA256
        == "377188bd48bacdd588c59510d50be16cd6bb7c32f21d7fc55a1f24e9a566d5bb"
    )
    assert subject.CONFIRM == "EXECUTE-CONFIRMED-DESKTOP-STABLE-BOOTSTRAP"


def test_source_has_no_arbitrary_shell_or_gui_automation() -> None:
    raw = Path(subject.__file__).read_text(encoding="utf-8")
    assert "shell=False" in raw
    assert "Invoke-Expression" not in raw
    assert "pyautogui" not in raw
    assert "keyboard." not in raw
    assert "mouse_event" not in raw
    assert "shutdown" not in raw.lower()


def test_evidence_path_must_stay_inside_workspace(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    inside = subject.validate_evidence_path(Path("artifacts/evidence.json"))
    assert inside == (tmp_path / "artifacts" / "evidence.json").resolve()
