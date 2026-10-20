"""Physical Desktop preflight for the Worker Pool durable S3 transport.

The route contains no credential material.  The credential is decrypted only by
``desktop_worker_s3_credentials.run_with_s3_client`` and is passed directly to a
bounded boto3 client.  The verified Worker Pool checkout supplies the transport
implementation; this host-specific wrapper does not duplicate its S3 protocol.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable


sys.dont_write_bytecode = True
SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import desktop_worker_s3_credentials as credentials  # noqa: E402


SCHEMA_VERSION = "1.0.0"
CONTRACT = "desktop-worker-s3-physical-preflight-v1"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SAFE_REASONS = {
    "correlation_id_invalid",
    "expected_identity_invalid",
    "runtime_checkout_invalid",
    "worker_pool_checkout_invalid",
    "worker_pool_contract_invalid",
    "s3_preflight_failed",
    "aws_environment_mutated",
    "evidence_path_invalid",
    "evidence_write_failed",
    "credential_operation_blocked",
}


class PhysicalPreflightError(RuntimeError):
    """Closed-set failure that is safe to emit without leaking dependencies."""

    def __init__(self, code: str):
        self.code = code if code in SAFE_REASONS else "s3_preflight_failed"
        super().__init__(self.code)


@dataclass(frozen=True)
class CheckoutIdentity:
    root: Path
    head: str
    tree: str


@dataclass(frozen=True)
class WorkerTransportContract:
    config_type: type[Any]
    transport_type: type[Any]


GitRunner = Callable[[Path, tuple[str, ...]], str]
CheckoutVerifier = Callable[[Path, str, str, str], CheckoutIdentity]
ContractLoader = Callable[[CheckoutIdentity], WorkerTransportContract]
CredentialRunner = Callable[[credentials.S3Route, Callable[[Any, credentials.S3Route], Any]], Any]


def _git_output(root: Path, arguments: tuple[str, ...]) -> str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        completed = subprocess.run(
            [
                "git",
                "-c", "core.fsmonitor=false",
                "-c", "core.untrackedCache=false",
                *arguments,
            ],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PhysicalPreflightError("worker_pool_checkout_invalid") from None
    if completed.returncode != 0:
        raise PhysicalPreflightError("worker_pool_checkout_invalid")
    return completed.stdout.strip()


def _same_physical_path(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _verify_checkout(
    root: Path,
    expected_head: str,
    expected_tree: str,
    kind: str,
    *,
    git_runner: GitRunner = _git_output,
) -> CheckoutIdentity:
    reason = "runtime_checkout_invalid" if kind == "runtime" else "worker_pool_checkout_invalid"
    if kind not in {"runtime", "worker_pool"}:
        raise PhysicalPreflightError("worker_pool_checkout_invalid")
    if not SHA40.fullmatch(expected_head) or not SHA40.fullmatch(expected_tree):
        raise PhysicalPreflightError("expected_identity_invalid")
    try:
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise PhysicalPreflightError(reason)
        resolved = root.resolve(strict=True)
        top_level = Path(git_runner(resolved, ("rev-parse", "--show-toplevel")))
        if not top_level.is_absolute() or not _same_physical_path(resolved, top_level):
            raise PhysicalPreflightError(reason)
        head = git_runner(resolved, ("rev-parse", "--verify", "HEAD"))
        tree = git_runner(resolved, ("rev-parse", "--verify", "HEAD^{tree}"))
        status = git_runner(
            resolved,
            (
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignored=matching",
                "-z",
            ),
        )
        index_state = git_runner(resolved, ("ls-files", "-v", "-z"))
    except PhysicalPreflightError as error:
        if error.code == "expected_identity_invalid":
            raise
        raise PhysicalPreflightError(reason) from None
    except (OSError, RuntimeError, ValueError):
        raise PhysicalPreflightError(reason) from None
    index_entries = [entry for entry in index_state.split("\0") if entry]
    if (
        head != expected_head
        or tree != expected_tree
        or status
        or any(not entry.startswith("H ") for entry in index_entries)
    ):
        raise PhysicalPreflightError(reason)
    return CheckoutIdentity(resolved, head, tree)


def _load_worker_transport(checkout: CheckoutIdentity) -> WorkerTransportContract:
    expected_module = checkout.root / "app" / "s3_git_bundle_artifact.py"
    expected_native = checkout.root / "app" / "native_one_shot.py"
    if any(
        path.is_symlink() or not path.is_file()
        for path in (expected_module, expected_native)
    ):
        raise PhysicalPreflightError("worker_pool_contract_invalid")
    previous_app_modules = {
        name for name in sys.modules if name == "app" or name.startswith("app.")
    }
    if previous_app_modules:
        raise PhysicalPreflightError("worker_pool_contract_invalid")
    inserted = str(checkout.root)
    sys.path.insert(0, inserted)
    try:
        importlib.invalidate_caches()
        module = importlib.import_module("app.s3_git_bundle_artifact")
        source = getattr(module, "__file__", None)
        if not isinstance(source, str) or not _same_physical_path(
            Path(source), expected_module,
        ):
            raise PhysicalPreflightError("worker_pool_contract_invalid")
        config_type = getattr(module, "S3ArtifactConfig", None)
        transport_type = getattr(module, "S3GitBundleArtifactTransport", None)
        if not isinstance(config_type, type) or not isinstance(transport_type, type):
            raise PhysicalPreflightError("worker_pool_contract_invalid")
        return WorkerTransportContract(config_type, transport_type)
    except PhysicalPreflightError:
        raise
    except Exception:
        raise PhysicalPreflightError("worker_pool_contract_invalid") from None
    finally:
        if sys.path and sys.path[0] == inserted:
            sys.path.pop(0)
        else:
            try:
                sys.path.remove(inserted)
            except ValueError:
                pass
        for name in tuple(sys.modules):
            if (
                name == "app" or name.startswith("app.")
            ) and name not in previous_app_modules:
                sys.modules.pop(name, None)


def _route_binding_sha256(route: credentials.S3Route) -> str:
    raw = json.dumps(
        {
            "bucket": route.bucket,
            "endpoint_url": route.endpoint_url,
            "key_prefix": route.key_prefix,
            "region": route.region,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def execute_preflight(
    *,
    expected_runtime_sha: str,
    expected_runtime_tree: str,
    worker_pool_root: Path,
    expected_worker_pool_sha: str,
    expected_worker_pool_tree: str,
    correlation_id: str,
    route: credentials.S3Route,
    checkout_verifier: CheckoutVerifier = _verify_checkout,
    contract_loader: ContractLoader = _load_worker_transport,
    credential_runner: CredentialRunner = credentials.run_with_s3_client,
) -> dict[str, Any]:
    if not SAFE_ID.fullmatch(correlation_id):
        raise PhysicalPreflightError("correlation_id_invalid")
    runtime = checkout_verifier(
        REPOSITORY_ROOT,
        expected_runtime_sha,
        expected_runtime_tree,
        "runtime",
    )
    worker = checkout_verifier(
        worker_pool_root,
        expected_worker_pool_sha,
        expected_worker_pool_tree,
        "worker_pool",
    )
    contract = contract_loader(worker)
    before_aws = {
        key: value for key, value in os.environ.items() if key.upper().startswith("AWS_")
    }
    callback_calls = 0
    callback_failed = False

    def preflight(client: Any, actual_route: credentials.S3Route) -> None:
        nonlocal callback_calls, callback_failed
        callback_calls += 1
        try:
            if actual_route != route:
                raise PhysicalPreflightError("s3_preflight_failed")
            config = contract.config_type(
                bucket=actual_route.bucket,
                region=actual_route.region,
                key_prefix=actual_route.key_prefix,
                endpoint_url=actual_route.endpoint_url,
            )
            transport = contract.transport_type(config, client)
            transport.preflight()
        except Exception:
            # The credential wrapper intentionally sanitizes callback errors.
            # Preserve a safe local outcome so transport failures remain
            # distinguishable from DPAPI/client-creation failures.
            callback_failed = True

    credential_failure = False
    try:
        credential_runner(route, preflight)
    except credentials.CredentialBootstrapError:
        credential_failure = True
    except Exception:
        credential_failure = True

    after_aws = {
        key: value for key, value in os.environ.items() if key.upper().startswith("AWS_")
    }
    if after_aws != before_aws:
        for key in tuple(os.environ):
            if key.upper().startswith("AWS_"):
                os.environ.pop(key, None)
        os.environ.update(before_aws)
        raise PhysicalPreflightError("aws_environment_mutated")
    if credential_failure:
        raise PhysicalPreflightError("credential_operation_blocked")
    if callback_calls != 1 or callback_failed:
        raise PhysicalPreflightError("s3_preflight_failed")
    runtime_after = checkout_verifier(
        REPOSITORY_ROOT,
        expected_runtime_sha,
        expected_runtime_tree,
        "runtime",
    )
    worker_after = checkout_verifier(
        worker_pool_root,
        expected_worker_pool_sha,
        expected_worker_pool_tree,
        "worker_pool",
    )
    if runtime_after != runtime or worker_after != worker:
        raise PhysicalPreflightError("worker_pool_checkout_invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "contract": CONTRACT,
        "result": "DESKTOP_WORKER_S3_PREFLIGHT_PASSED",
        "correlation_id": correlation_id,
        "host": credentials.EXPECTED_HOST,
        "runtime_sha": runtime.head,
        "runtime_tree": runtime.tree,
        "worker_pool_sha": worker.head,
        "worker_pool_tree": worker.tree,
        "route_binding_sha256": _route_binding_sha256(route),
        "conditional_write_and_exact_readback": True,
        "checkout_revalidated_after_network_effect": True,
        "current_process_dpapi_identity_validated": True,
        "s4u_identity_claimed_by_script": False,
        "credential_values_exposed": False,
        "route_values_exposed": False,
        "process_global_aws_environment_mutated": False,
        "task_executed": False,
    }


def _safe_blocked(reason: str, correlation_id: str | None) -> dict[str, Any]:
    safe_id = correlation_id if correlation_id and SAFE_ID.fullmatch(correlation_id) else None
    return {
        "schema_version": SCHEMA_VERSION,
        "contract": CONTRACT,
        "result": "DESKTOP_WORKER_S3_PREFLIGHT_BLOCKED",
        "reason": reason if reason in SAFE_REASONS else "s3_preflight_failed",
        "correlation_id": safe_id,
        "credential_values_exposed": False,
        "route_values_exposed": False,
        "task_executed": False,
    }


def _validate_evidence_path(
    path: Path,
    *,
    additional_forbidden_roots: tuple[Path, ...] = (),
) -> Path:
    try:
        if not path.is_absolute() or path.is_symlink():
            raise PhysicalPreflightError("evidence_path_invalid")
        destination = path.resolve(strict=False)
        repository = REPOSITORY_ROOT.resolve(strict=True)
        if destination == repository or repository in destination.parents:
            raise PhysicalPreflightError("evidence_path_invalid")
        for candidate in additional_forbidden_roots:
            root = candidate.resolve(strict=True)
            if destination == root or root in destination.parents:
                raise PhysicalPreflightError("evidence_path_invalid")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.parent.is_symlink() or not path.parent.is_dir():
            raise PhysicalPreflightError("evidence_path_invalid")
        return destination
    except PhysicalPreflightError:
        raise
    except OSError:
        raise PhysicalPreflightError("evidence_path_invalid") from None


def _write_evidence(
    path: Path,
    payload: dict[str, Any],
    *,
    additional_forbidden_roots: tuple[Path, ...] = (),
) -> None:
    try:
        destination = _validate_evidence_path(
            path,
            additional_forbidden_roots=additional_forbidden_roots,
        )
        encoded = (
            json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
        descriptor, pending_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".pending", dir=destination.parent,
        )
        pending = Path(pending_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            pending.chmod(0o600)
            os.replace(pending, destination)
        finally:
            pending.unlink(missing_ok=True)
    except PhysicalPreflightError:
        raise
    except OSError:
        raise PhysicalPreflightError("evidence_write_failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the Desktop DPAPI identity against the Worker Pool S3 transport",
    )
    parser.add_argument("--expected-runtime-sha", required=True)
    parser.add_argument("--expected-runtime-tree", required=True)
    parser.add_argument("--worker-pool-root", type=Path, required=True)
    parser.add_argument("--expected-worker-pool-sha", required=True)
    parser.add_argument("--expected-worker-pool-tree", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--endpoint-url", required=True)
    parser.add_argument("--key-prefix", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    correlation_id = arguments.correlation_id
    try:
        _validate_evidence_path(
            arguments.output,
            additional_forbidden_roots=(arguments.worker_pool_root,),
        )
        route = credentials.S3Route(
            bucket=arguments.bucket,
            region=arguments.region,
            endpoint_url=arguments.endpoint_url,
            key_prefix=arguments.key_prefix,
        )
        result = execute_preflight(
            expected_runtime_sha=arguments.expected_runtime_sha,
            expected_runtime_tree=arguments.expected_runtime_tree,
            worker_pool_root=arguments.worker_pool_root,
            expected_worker_pool_sha=arguments.expected_worker_pool_sha,
            expected_worker_pool_tree=arguments.expected_worker_pool_tree,
            correlation_id=correlation_id,
            route=route,
        )
        _write_evidence(
            arguments.output,
            result,
            additional_forbidden_roots=(arguments.worker_pool_root,),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except credentials.CredentialBootstrapError:
        blocked = _safe_blocked("credential_operation_blocked", correlation_id)
    except PhysicalPreflightError as error:
        blocked = _safe_blocked(error.code, correlation_id)
    except Exception:
        blocked = _safe_blocked("s3_preflight_failed", correlation_id)
    try:
        _write_evidence(
            arguments.output,
            blocked,
            additional_forbidden_roots=(arguments.worker_pool_root,),
        )
    except PhysicalPreflightError:
        pass
    print(json.dumps(blocked, ensure_ascii=True, sort_keys=True), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
