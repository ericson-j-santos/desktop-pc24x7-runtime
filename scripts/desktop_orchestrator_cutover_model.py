"""Fail-closed Desktop Orchestrator cutover contract and disposable transaction drill.

NO executable production/DEV cutover entrypoint. Only a disposable fixture can
run the rename+rollback drill. Actual service startup, Windows auth, credential
handling and real cutover remain separate governed capabilities.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Callable

HOST = "DESKTOP-PDQK954"
OLD_SHA = "33f312d0ac4c25d8420d4589fa0e8bc21d943ebd"
TARGET_REPO = "ericson-j-santos/reqsys-engineering-orchestrator"
TARGET_SHA = "e23cc492827de6129ce78e9f4fc8bf592ce17ee8"
SIMULATION_MARKER = ".isolated-cutover-test-only"
SIMULATION_VALUE = "DISPOSABLE-TEST-FIXTURE-V1"
JOURNAL = "transaction-state.json"
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
APPROVAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{9,119}\Z")

# These gates cannot be set through an environment variable to authorize an
# actual host mutation. They support a reviewable plan, never an apply command.
REQUIRED_GATES = (
    "desktop_main_protected",
    "orchestrator_main_protected",
    "old_runtime_physical_sha_verified",
    "target_sha_in_approved_main",
    "source_artifact_digest_verified",
    "local_code_backup_verified",
    "dpapi_state_restore_verified",
    "shadow_service_e2e_verified",
    "legacy_unsafe_run_cancelled",
    "permanent_bootstrap_staged",
    "service_rollback_rehearsed",
    "risk3_cutover_approved",
)


class CutoverFailure(ValueError):
    def __init__(self, code: str, *, restored: bool = False):
        super().__init__(code)
        self.code = code
        self.restored = restored


@dataclass(frozen=True)
class CutoverEvidence:
    host: str
    environment: str
    old_sha: str
    target_repo: str
    target_sha: str
    approval_correlation_id: str
    gates: dict[str, bool]


def review(evidence: CutoverEvidence) -> dict[str, Any]:
    """Advisory only; no mutable object, API call or host action."""
    missing = [
        name for name in REQUIRED_GATES if evidence.gates.get(name) is not True
    ]
    if (evidence.host != HOST or evidence.environment != "dev"
        or evidence.old_sha != OLD_SHA or evidence.target_repo != TARGET_REPO
        or evidence.target_sha != TARGET_SHA
        or not APPROVAL_RE.fullmatch(evidence.approval_correlation_id)):
        return {
            "result": "CUTOVER_IDENTITY_BLOCKED", "missing_gates": list(REQUIRED_GATES),
            "service_restarted": False, "recovery_allowed": False,
        }
    return {
        "result": "CUTOVER_REVIEWABLE" if not missing else "CUTOVER_GATES_BLOCKED",
        "missing_gates": missing, "old_sha": OLD_SHA,
        "target_sha": TARGET_SHA, "service_restarted": False,
        "recovery_allowed": False,  # A separate risk-3 executor is mandatory.
        "simulated_only": True,
    }


def _read_sha(root: Path) -> str:
    try:
        with (root / "runtime-version.json").open("r", encoding="utf-8") as stream:
            obj = json.load(stream)
    except (OSError, ValueError):
        raise CutoverFailure("RELEASE_METADATA_INVALID") from None
    if (not isinstance(obj, dict) or obj.get("schema_version") != 1
        or not isinstance(obj.get("source_sha"), str)
        or not SHA_RE.fullmatch(obj["source_sha"])):
        raise CutoverFailure("RELEASE_METADATA_INVALID")
    return obj["source_sha"]


def _digest(root: Path) -> str:
    path = root / "code-proof.txt"
    if path.is_symlink() or not path.is_file():
        raise CutoverFailure("RELEASE_CONTENT_MISSING")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _guard_disposable(home: Path) -> None:
    # No caller can use the physical C:\dev\... runtime with this helper.
    actual = home.resolve()
    scratch = Path(tempfile.gettempdir()).resolve()
    if actual == scratch or not actual.is_relative_to(scratch):
        raise CutoverFailure("SIMULATION_SCOPE_FORBIDDEN")
    marker = actual / SIMULATION_MARKER
    if marker.is_symlink() or not marker.is_file():
        raise CutoverFailure("SIMULATION_MARKER_MISSING")
    if marker.read_text("utf-8") != SIMULATION_VALUE:
        raise CutoverFailure("SIMULATION_MARKER_INVALID")
    for subpath in ("active", "candidate", "previous"):
        leaf = actual / subpath
        if leaf.is_symlink():
            raise CutoverFailure("SIMULATION_REDIRECTED")


def _read_journal(home: Path) -> dict[str, Any] | None:
    p = home / JOURNAL
    if not p.exists():
        return None
    if p.is_symlink():
        raise CutoverFailure("JOURNAL_REDIRECTED")
    try:
        obj = json.loads(p.read_text("utf-8"))
    except (OSError, ValueError):
        raise CutoverFailure("JOURNAL_INVALID") from None
    if (not isinstance(obj, dict) or obj.get("schema") != 1
        or obj.get("old_sha") != OLD_SHA or obj.get("target_sha") != TARGET_SHA
        or obj.get("state") not in ("SWITCHING", "VERIFYING", "COMMITTED")
        or not isinstance(obj.get("old_digest"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", obj["old_digest"])
        or not isinstance(obj.get("target_digest"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", obj["target_digest"])):
        raise CutoverFailure("JOURNAL_INVALID")
    return obj


def _write_journal(home: Path, state: str, *, correlation_id: str,
                   old_digest: str, target_digest: str) -> None:
    payload = {
        "schema": 1, "state": state,
        "old_sha": OLD_SHA, "target_sha": TARGET_SHA,
        "correlation_id": correlation_id,
        "old_digest": old_digest, "target_digest": target_digest,
    }
    temp = home / ".transaction-journal.tmp"
    if temp.exists() or temp.is_symlink():
        raise CutoverFailure("JOURNAL_TEMP_CONFLICT")
    with temp.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True)
    os.replace(temp, home / JOURNAL)


def _restore_old(home: Path, old_digest: str, target_digest: str) -> None:
    active = home / "active"
    candidate = home / "candidate"
    previous = home / "previous"
    if previous.exists():
        if active.exists():
            if _read_sha(active) != TARGET_SHA or candidate.exists():
                raise CutoverFailure("ROLLBACK_TARGET_AMBIGUOUS")
            active.rename(candidate)
        previous.rename(active)
    if _read_sha(active) != OLD_SHA or _digest(active) != old_digest:
        raise CutoverFailure("ROLLBACK_IDENTITY_FAILED")
    if candidate.exists() and _digest(candidate) != target_digest:
        raise CutoverFailure("ROLLBACK_CANDIDATE_CHANGED")


def simulate_transaction(
    home: Path, *, correlation_id: str,
    health: Callable[[str], dict[str, Any]],
    inject_at: str | None = None,
) -> dict[str, Any]:
    """A filesystem drill in TEMP ONLY. Does not start/stop any real process."""
    _guard_disposable(home)
    if not APPROVAL_RE.fullmatch(correlation_id):
        raise CutoverFailure("CORRELATION_INVALID")
    if inject_at not in (None, "after_old_move", "after_new_move", "health_failed"):
        raise CutoverFailure("FAILPOINT_INVALID")
    current = home / "active"
    incoming = home / "candidate"
    previous = home / "previous"
    state = _read_journal(home)
    if state:
        if state["state"] != "COMMITTED":
            raise CutoverFailure("INCOMPLETE_TRANSACTION_REQUIRES_RECOVERY")
        if (_read_sha(current) == TARGET_SHA and _read_sha(previous) == OLD_SHA
            and state.get("correlation_id") == correlation_id
            and _digest(current) == state["target_digest"]
            and _digest(previous) == state["old_digest"]):
            return {
                "result": "SIMULATED_REPLAY", "replayed": True,
                "service_restarted": False, "recovery_allowed": False,
            }
        raise CutoverFailure("COMMITTED_TRANSACTION_IDENTITY_MISMATCH")
    if previous.exists() or not current.is_dir() or not incoming.is_dir():
        raise CutoverFailure("RELEASE_LAYOUT_INVALID")
    if _read_sha(current) != OLD_SHA or _read_sha(incoming) != TARGET_SHA:
        raise CutoverFailure("RELEASE_SHA_MISMATCH")
    old_digest, target_digest = _digest(current), _digest(incoming)
    lock = home / ".transaction.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise CutoverFailure("TRANSACTION_LOCKED") from None
    os.close(fd)
    try:
        _write_journal(home, "SWITCHING", correlation_id=correlation_id,
                       old_digest=old_digest, target_digest=target_digest)
        try:
            current.rename(previous)
            if inject_at == "after_old_move":
                raise CutoverFailure("INJECTED_SWITCH_FAILURE")
            incoming.rename(current)
            if inject_at == "after_new_move":
                raise CutoverFailure("INJECTED_SWITCH_FAILURE")
            _write_journal(home, "VERIFYING", correlation_id=correlation_id,
                           old_digest=old_digest, target_digest=target_digest)
            outcome = health(TARGET_SHA)
            if (inject_at == "health_failed"
                or outcome.get("ready") is not True
                or outcome.get("runtime_sha") != TARGET_SHA
                or outcome.get("worker_instance_changed") is not True
                or _read_sha(current) != TARGET_SHA
                or _digest(current) != target_digest):
                raise CutoverFailure("POST_SWITCH_HEALTH_INVALID")
            if _read_sha(previous) != OLD_SHA or _digest(previous) != old_digest:
                raise CutoverFailure("PREVIOUS_RELEASE_CHANGED")
        except Exception:
            try:
                _restore_old(home, old_digest, target_digest)
            except Exception:
                raise CutoverFailure("ROLLBACK_NOT_VERIFIED", restored=False) from None
            # Deliberately keep failed journal to prevent unsafe automatic retry.
            raise CutoverFailure("SIMULATED_ROLLBACK_VERIFIED", restored=True) from None
        _write_journal(home, "COMMITTED", correlation_id=correlation_id,
                       old_digest=old_digest, target_digest=target_digest)
        return {
            "result": "SIMULATED_SWITCH_COMMITTED",
            "old_digest": old_digest,
            "target_digest": target_digest,
            "replayed": False, "service_restarted": False,
            "recovery_allowed": False, "simulated_only": True,
        }
    finally:
        lock.unlink(missing_ok=True)


def main() -> int:
    # There is intentionally NO 'apply', 'activate', 'restart' or 'rollback'
    # CLI command; the reviewed risk-3 executor must be designed separately.
    print(json.dumps({
        "result": "CUTOVER_EXECUTION_NOT_IMPLEMENTED",
        "host": HOST, "current_sha": OLD_SHA, "target_sha": TARGET_SHA,
        "simulated_only": True, "service_restarted": False,
        "recovery_allowed": False,
    }, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
