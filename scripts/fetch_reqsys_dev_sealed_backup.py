"""Fetch one pinned encrypted ReqSys DEV artifact with existing owner gh auth.

This helper never exports tokens, installs tools, creates credentials, accepts a
URL/repository/output path, decrypts data, or activates a service.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import stat
import subprocess
import threading
import time
import zipfile

SOURCE_REPO = "ericson-j-santos/reqsys-v2-enterprise-real"
OWNER = "ericson-j-santos"
SOURCE_BRANCH = "fix/self-hosted-dev-restore-20261003"
SOURCE_WORKFLOW = ".github/workflows/noteri-desktop-network-probe.yml"
SOURCE_JOB = "Inspect validated backup metadata on Noteri"
SOURCE_RUNNER = "Noteri"
SOURCE_LABELS = {"self-hosted", "Windows", "X64", "noteri", "reqsys-dev"}
TARGET_HOST = "DESKTOP-PDQK954"
CIPHER_SCHEMA = "reqsys-dev-noteri-pc24x7-backup-v1"
SNAPSHOT_ID = "c017334cd021ec734bfecae44622c0196b44b4a386d646aebd2ec5c47d6e53f0"
SQLITE_SHA256 = "f300a4e003bcb1195aab7dbf2a3fbe31c164cddbf1abd55f5619cd9c4043cd7a"
SQLITE_BYTES = 237568
MAX_BYTES = 1_048_576
TTL_SECONDS = 3600
HEADER_FIELDS = {
    "schema", "source_host", "target_host", "snapshot_id", "sqlite_sha256",
    "sqlite_bytes", "created_at", "expires_at", "source_run_id", "source_sha",
    "recipient_sha256",
}


class FetchError(RuntimeError):
    def __init__(self, code: str):
        if not re.fullmatch(r"[a-z0-9_]+", code):
            code = "fetch_operation_failed"
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise FetchError(code)


def strict_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "json_duplicate_key")
        result[key] = value
    return result


def invalid_json_number(_value: str) -> None:
    raise FetchError("json_invalid_number")


def parse_json(data: bytes) -> dict:
    require(0 < len(data) <= MAX_BYTES, "json_size_invalid")
    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=strict_object,
            parse_constant=invalid_json_number,
        )
    except (ValueError, UnicodeError) as exc:
        raise FetchError("json_invalid") from exc
    require(isinstance(value, dict), "json_object_required")
    return value


def is_int(value: object, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value < 2**63


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def local_gh_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"):
        env.pop(key, None)
    env["GH_HOST"] = "github.com"
    env["GH_PROMPT_DISABLED"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"
    return env


def find_gh() -> str:
    found = shutil.which("gh")
    if found:
        return found
    candidates = (
        Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "GitHub CLI/gh.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/GitHub CLI/gh.exe",
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise FetchError("existing_local_gh_unavailable")


def capture_bounded(argv: list[str], env: dict[str, str], limit: int, timeout: float) -> bytes:
    """Read finite bytes from gh; stderr is discarded and prompts have no stdin."""
    events: queue.Queue = queue.Queue(maxsize=2)
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False, env=env,
        )
    except OSError as exc:
        raise FetchError("existing_local_gh_unavailable") from exc

    def read_stdout() -> None:
        try:
            assert process.stdout is not None
            while True:
                chunk = process.stdout.read(65536)
                events.put(("data", chunk))
                if not chunk:
                    return
        except Exception:
            events.put(("error", b""))

    reader = threading.Thread(target=read_stdout, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    result = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "github_get_timeout")
            try:
                kind, chunk = events.get(timeout=remaining)
            except queue.Empty as exc:
                raise FetchError("github_get_timeout") from exc
            require(kind == "data", "github_get_stream_failed")
            if not chunk:
                break
            require(len(result) + len(chunk) <= limit, "github_get_size_limit")
            result.extend(chunk)
        remaining = deadline - time.monotonic()
        require(remaining > 0, "github_get_timeout")
        try:
            status = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise FetchError("github_get_timeout") from exc
        require(status == 0, "github_get_denied_or_failed")
        return bytes(result)
    finally:
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        if process.stdout is not None:
            process.stdout.close()
        reader.join(timeout=0.1)


class ExistingOwnerGh:
    def __init__(self, run_id: int, artifact_id: int):
        self.binary = find_gh()
        self.env = local_gh_env()
        self.deadline = time.monotonic() + 180
        prefix = f"repos/{SOURCE_REPO}/actions"
        self.allowed = {
            f"{prefix}/runs/{run_id}",
            f"{prefix}/runs/{run_id}/jobs?per_page=100",
            f"{prefix}/artifacts/{artifact_id}",
            f"{prefix}/artifacts/{artifact_id}/zip",
        }

    def _capture(self, argv: list[str], limit: int, timeout: int) -> bytes:
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "fetch_total_timeout")
        return capture_bounded(argv, self.env, limit, min(timeout, remaining))

    def verify_owner(self) -> None:
        identity = self._capture(
            [self.binary, "api", "--hostname", "github.com", "--method", "GET",
             "user", "--jq", ".login"], 256, 30,
        )
        try:
            login = identity.decode("ascii").strip()
        except UnicodeError as exc:
            raise FetchError("existing_local_gh_owner_unverified") from exc
        require(login.casefold() == OWNER.casefold(), "existing_local_gh_owner_unverified")

    def get(self, endpoint: str, binary: bool = False) -> bytes:
        require(endpoint in self.allowed, "github_endpoint_not_allowed")
        require(binary == endpoint.endswith("/zip"), "github_response_mode_invalid")
        return self._capture(
            [self.binary, "api", "--hostname", "github.com", "--method", "GET",
             endpoint, "-H", "Accept: application/vnd.github+json"],
            MAX_BYTES, 60 if binary else 30,
        )


def validate_run(run: dict, run_id: int, source_sha: str) -> None:
    require(
        run.get("id") == run_id and is_int(run.get("id"), 1)
        and run.get("head_sha") == source_sha
        and run.get("head_branch") == SOURCE_BRANCH
        and run.get("path") == SOURCE_WORKFLOW
        and run.get("event") == "push"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "source_run_unverified",
    )
    for key in ("repository", "head_repository"):
        repo = run.get(key)
        require(isinstance(repo, dict) and repo.get("full_name") == SOURCE_REPO,
                "source_repository_unverified")


def validate_jobs(payload: dict, run_id: int, source_sha: str) -> None:
    jobs = payload.get("jobs")
    require(isinstance(jobs, list) and len(jobs) <= 100, "source_jobs_unverified")
    require(payload.get("total_count") == len(jobs), "source_jobs_incomplete")
    matches = [job for job in jobs if isinstance(job, dict) and job.get("name") == SOURCE_JOB]
    require(len(matches) == 1, "source_backup_job_unverified")
    job = matches[0]
    labels = job.get("labels")
    require(
        job.get("run_id") == run_id and job.get("head_sha") == source_sha
        and job.get("status") == "completed" and job.get("conclusion") == "success"
        and job.get("runner_name") == SOURCE_RUNNER and is_int(job.get("runner_id"), 1)
        and isinstance(labels, list) and all(isinstance(item, str) for item in labels)
        and SOURCE_LABELS.issubset(set(labels)),
        "source_backup_job_unverified",
    )


def validate_artifact(artifact: dict, run_id: int, source_sha: str,
                      artifact_id: int, artifact_sha256: str) -> None:
    source = artifact.get("workflow_run")
    require(
        artifact.get("id") == artifact_id and is_int(artifact.get("id"), 1)
        and artifact.get("name") == f"reqsys-dev-backup-restic-{run_id}"
        and artifact.get("expired") is False
        and is_int(artifact.get("size_in_bytes"), 1)
        and artifact["size_in_bytes"] <= MAX_BYTES
        and artifact.get("digest") == f"sha256:{artifact_sha256}"
        and isinstance(source, dict) and source.get("id") == run_id
        and source.get("head_sha") == source_sha and source.get("head_branch") == SOURCE_BRANCH,
        "source_ciphertext_artifact_unverified",
    )


def decode_cipher_field(value: object, expected_bytes: int) -> None:
    require(isinstance(value, str), "ciphertext_field_invalid")
    require(len(value) == 4 * ((expected_bytes + 2) // 3), "ciphertext_field_invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise FetchError("ciphertext_field_invalid") from exc
    require(len(decoded) == expected_bytes, "ciphertext_field_invalid")
    require(not decoded.startswith(b"SQLite format 3\x00"), "plaintext_artifact_rejected")


def validate_envelope(data: bytes, run_id: int, source_sha: str, now: int) -> None:
    envelope = parse_json(data)
    require(set(envelope) == {"header", "nonce_b64", "sealed_key_b64", "ciphertext_b64"},
            "ciphertext_schema_invalid")
    header = envelope.get("header")
    require(isinstance(header, dict) and set(header) == HEADER_FIELDS,
            "ciphertext_schema_invalid")
    expected = {
        "schema": CIPHER_SCHEMA, "source_host": SOURCE_RUNNER, "target_host": TARGET_HOST,
        "snapshot_id": SNAPSHOT_ID, "sqlite_sha256": SQLITE_SHA256,
        "sqlite_bytes": SQLITE_BYTES, "source_run_id": run_id, "source_sha": source_sha,
    }
    require(all(header.get(key) == value for key, value in expected.items()),
            "ciphertext_binding_invalid")
    require(is_int(header.get("sqlite_bytes"), 1) and is_int(header.get("source_run_id"), 1),
            "ciphertext_binding_invalid")
    created, expires = header.get("created_at"), header.get("expires_at")
    require(
        is_int(created, 1) and is_int(expires, 1)
        and expires == created + TTL_SECONDS and created <= now + 300 and expires > now,
        "ciphertext_expired_or_invalid",
    )
    require(isinstance(header.get("recipient_sha256"), str)
            and re.fullmatch(r"[a-f0-9]{64}", header["recipient_sha256"]) is not None,
            "ciphertext_recipient_invalid")
    decode_cipher_field(envelope["nonce_b64"], 12)
    decode_cipher_field(envelope["sealed_key_b64"], 384)
    decode_cipher_field(envelope["ciphertext_b64"], SQLITE_BYTES + 16)


def extract_envelope(archive: bytes) -> bytes:
    require(0 < len(archive) <= MAX_BYTES, "artifact_archive_size_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            entries = zipped.infolist()
            require(len(entries) == 1, "artifact_archive_members_invalid")
            entry = entries[0]
            mode = (entry.external_attr >> 16) & 0xFFFF
            require(
                entry.filename == "envelope.json" and not entry.is_dir()
                and not (entry.flag_bits & 1)
                and (stat.S_IFMT(mode) in (0, stat.S_IFREG))
                and 0 < entry.file_size <= MAX_BYTES
                and 0 < entry.compress_size <= MAX_BYTES
                and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                "artifact_archive_members_invalid",
            )
            with zipped.open(entry) as source:
                data = source.read(MAX_BYTES + 1)
            require(0 < len(data) <= MAX_BYTES and len(data) == entry.file_size,
                    "artifact_envelope_size_invalid")
            return data
    except FetchError:
        raise
    except (zipfile.BadZipFile, RuntimeError, OSError, ValueError) as exc:
        raise FetchError("artifact_archive_invalid") from exc


def reject_reparse(path: Path) -> None:
    for part in (path, *path.parents):
        if not part.exists() and not part.is_symlink():
            continue
        info = part.lstat()
        require(not part.is_symlink()
                and not (getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)),
                "output_reparse_point_rejected")


def output_path() -> Path:
    raw = os.environ.get("RUNNER_TEMP", "")
    require(bool(raw) and "\n" not in raw and "\r" not in raw, "runner_temp_unavailable")
    root = Path(raw)
    require(root.is_absolute() and root.is_dir(), "runner_temp_unavailable")
    reject_reparse(root)
    folder = root / "dev-backup-input"
    reject_reparse(folder)
    folder.mkdir(exist_ok=True)
    require(folder.is_dir(), "output_directory_invalid")
    destination = folder / "envelope.json"
    reject_reparse(destination)
    return destination


def preserve_write(destination: Path, data: bytes) -> bool:
    """False means an identical ciphertext file was already present."""
    reject_reparse(destination)
    if destination.exists():
        require(destination.is_file() and destination.stat().st_size <= MAX_BYTES,
                "existing_envelope_conflict")
        require(destination.read_bytes() == data, "existing_envelope_conflict")
        return False
    try:
        with destination.open("xb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
    except FileExistsError:
        require(destination.is_file() and destination.stat().st_size <= MAX_BYTES
                and destination.read_bytes() == data, "existing_envelope_conflict")
        return False
    return True


def fetch(client: ExistingOwnerGh, run_id: int, source_sha: str, artifact_id: int,
          artifact_sha256: str, envelope_sha256: str, destination: Path, now: int) -> dict:
    client.verify_owner()
    prefix = f"repos/{SOURCE_REPO}/actions"
    validate_run(parse_json(client.get(f"{prefix}/runs/{run_id}")), run_id, source_sha)
    validate_jobs(parse_json(client.get(f"{prefix}/runs/{run_id}/jobs?per_page=100")),
                  run_id, source_sha)
    validate_artifact(
        parse_json(client.get(f"{prefix}/artifacts/{artifact_id}")),
        run_id, source_sha, artifact_id, artifact_sha256,
    )
    archive = client.get(f"{prefix}/artifacts/{artifact_id}/zip", binary=True)
    require(digest(archive) == artifact_sha256, "artifact_archive_sha256_mismatch")
    envelope = extract_envelope(archive)
    require(digest(envelope) == envelope_sha256, "artifact_envelope_sha256_mismatch")
    validate_envelope(envelope, run_id, source_sha, now)
    written = preserve_write(destination, envelope)
    return {
        "ok": True, "source_repository": SOURCE_REPO, "source_run_id": run_id,
        "source_sha": source_sha, "artifact_id": artifact_id,
        "artifact_sha256": artifact_sha256, "envelope_sha256": envelope_sha256,
        "envelope_bytes": len(envelope), "output_relative": "dev-backup-input/envelope.json",
        "file_created": written, "ciphertext_only": True,
        "credential_mode": "existing_local_owner_gh", "new_credentials_created": False,
        "secret_values_exposed": False, "services_activated": False,
    }


class SafeParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise FetchError("invalid_cli")


def positive_id(raw: str) -> int:
    require(re.fullmatch(r"[1-9][0-9]{0,18}", raw) is not None, "invalid_cli")
    value = int(raw)
    require(value < 2**63, "invalid_cli")
    return value


def sha40(raw: str) -> str:
    require(re.fullmatch(r"[a-f0-9]{40}", raw) is not None, "invalid_cli")
    return raw


def sha256(raw: str) -> str:
    require(re.fullmatch(r"[a-f0-9]{64}", raw) is not None, "invalid_cli")
    return raw


def main(argv: list[str] | None = None) -> int:
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument("--source-run-id", required=True, type=positive_id)
        parser.add_argument("--source-sha", required=True, type=sha40)
        parser.add_argument("--artifact-id", required=True, type=positive_id)
        parser.add_argument("--artifact-sha256", required=True, type=sha256)
        parser.add_argument("--envelope-sha256", required=True, type=sha256)
        args = parser.parse_args(argv)
        require(os.name == "nt" and socket.gethostname().casefold() == TARGET_HOST.casefold(),
                "target_host_unverified")
        destination = output_path()
        client = ExistingOwnerGh(args.source_run_id, args.artifact_id)
        evidence = fetch(
            client, args.source_run_id, args.source_sha, args.artifact_id,
            args.artifact_sha256, args.envelope_sha256, destination, int(time.time()),
        )
        print(json.dumps(evidence, sort_keys=True))
        return 0
    except FetchError as exc:
        print(json.dumps({"ok": False, "code": exc.code, "secret_values_exposed": False}))
        return 2
    except Exception:
        print(json.dumps({"ok": False, "code": "fetch_operation_failed",
                          "secret_values_exposed": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
