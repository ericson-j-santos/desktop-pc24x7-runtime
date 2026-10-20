"""Offline contract tests for the physical Desktop S3 preflight."""
from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import desktop_worker_s3_credentials as credentials
import desktop_worker_s3_preflight as p


RUNTIME_SHA = "1" * 40
RUNTIME_TREE = "2" * 40
WORKER_SHA = "3" * 40
WORKER_TREE = "4" * 40
SECRET = "TEST-ONLY-MUST-NEVER-BE-EMITTED"


class FakeConfig:
    def __init__(self, **values: object):
        self.values = values


class FakeTransport:
    calls = 0

    def __init__(self, config: FakeConfig, client: object):
        self.config = config
        self.client = client

    def preflight(self) -> None:
        type(self).calls += 1


class FailingTransport(FakeTransport):
    def preflight(self) -> None:
        raise RuntimeError(SECRET)


class DesktopWorkerS3PreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.worker = self.root / "worker"
        self.worker.mkdir()
        self.route = credentials.S3Route(
            bucket="private-artifacts",
            region="us-east-2",
            endpoint_url="https://storage.example.invalid",
            key_prefix="worker/checkpoints",
        )
        FakeTransport.calls = 0

    def verifier(
        self, root: Path, expected_head: str, expected_tree: str, kind: str,
    ) -> p.CheckoutIdentity:
        selected = p.REPOSITORY_ROOT if kind == "runtime" else self.worker
        self.assertEqual(Path(root), selected)
        expected = (
            (RUNTIME_SHA, RUNTIME_TREE)
            if kind == "runtime"
            else (WORKER_SHA, WORKER_TREE)
        )
        self.assertEqual((expected_head, expected_tree), expected)
        return p.CheckoutIdentity(selected.resolve(), expected_head, expected_tree)

    @staticmethod
    def credential_runner(
        route: credentials.S3Route,
        callback: object,
    ) -> None:
        callback(object(), route)

    def execute(self, transport_type: type[FakeTransport] = FakeTransport) -> dict[str, object]:
        return p.execute_preflight(
            expected_runtime_sha=RUNTIME_SHA,
            expected_runtime_tree=RUNTIME_TREE,
            worker_pool_root=self.worker,
            expected_worker_pool_sha=WORKER_SHA,
            expected_worker_pool_tree=WORKER_TREE,
            correlation_id="physical-preflight-001",
            route=self.route,
            checkout_verifier=self.verifier,
            contract_loader=lambda _checkout: p.WorkerTransportContract(
                FakeConfig, transport_type,
            ),
            credential_runner=self.credential_runner,
        )

    def test_explicit_client_runs_real_transport_contract_without_exposing_route(self) -> None:
        before = {
            key: value for key, value in os.environ.items() if key.startswith("AWS_")
        }
        result = self.execute()
        rendered = json.dumps(result, sort_keys=True)
        after = {
            key: value for key, value in os.environ.items() if key.startswith("AWS_")
        }
        self.assertEqual(FakeTransport.calls, 1)
        self.assertEqual(result["result"], "DESKTOP_WORKER_S3_PREFLIGHT_PASSED")
        self.assertEqual(result["runtime_sha"], RUNTIME_SHA)
        self.assertEqual(result["worker_pool_sha"], WORKER_SHA)
        self.assertTrue(result["conditional_write_and_exact_readback"])
        self.assertFalse(result["s4u_identity_claimed_by_script"])
        self.assertNotIn(self.route.bucket, rendered)
        self.assertNotIn(self.route.endpoint_url, rendered)
        self.assertNotIn(self.route.key_prefix, rendered)
        self.assertEqual(after, before)

    def test_transport_failure_is_sanitized(self) -> None:
        with self.assertRaisesRegex(p.PhysicalPreflightError, "s3_preflight_failed") as caught:
            self.execute(FailingTransport)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_credential_failure_is_collapsed_to_safe_reason(self) -> None:
        def blocked(
            _route: credentials.S3Route,
            _callback: object,
        ) -> None:
            raise credentials.CredentialBootstrapError("s3_callback_failed")

        with self.assertRaisesRegex(
            p.PhysicalPreflightError, "credential_operation_blocked",
        ):
            p.execute_preflight(
                expected_runtime_sha=RUNTIME_SHA,
                expected_runtime_tree=RUNTIME_TREE,
                worker_pool_root=self.worker,
                expected_worker_pool_sha=WORKER_SHA,
                expected_worker_pool_tree=WORKER_TREE,
                correlation_id="physical-preflight-002",
                route=self.route,
                checkout_verifier=self.verifier,
                contract_loader=lambda _checkout: p.WorkerTransportContract(
                    FakeConfig, FakeTransport,
                ),
                credential_runner=blocked,
            )

    def test_missing_or_duplicate_callback_fails_closed(self) -> None:
        runners = (
            lambda _route, _callback: None,
            lambda route, callback: (callback(object(), route), callback(object(), route)),
        )
        for runner in runners:
            with self.subTest(runner=runner), self.assertRaisesRegex(
                p.PhysicalPreflightError, "s3_preflight_failed",
            ):
                p.execute_preflight(
                    expected_runtime_sha=RUNTIME_SHA,
                    expected_runtime_tree=RUNTIME_TREE,
                    worker_pool_root=self.worker,
                    expected_worker_pool_sha=WORKER_SHA,
                    expected_worker_pool_tree=WORKER_TREE,
                    correlation_id="physical-preflight-callback-control",
                    route=self.route,
                    checkout_verifier=self.verifier,
                    contract_loader=lambda _checkout: p.WorkerTransportContract(
                        FakeConfig, FakeTransport,
                    ),
                    credential_runner=runner,
                )

    def test_aws_environment_mutation_fails_closed(self) -> None:
        marker = "AWS_TEST_ONLY_PREFLIGHT_MUTATION"
        original = os.environ.get(marker)

        def mutating(
            route: credentials.S3Route,
            callback: object,
        ) -> None:
            callback(object(), route)
            os.environ[marker] = "unexpected"

        try:
            with self.assertRaisesRegex(
                p.PhysicalPreflightError, "aws_environment_mutated",
            ):
                p.execute_preflight(
                    expected_runtime_sha=RUNTIME_SHA,
                    expected_runtime_tree=RUNTIME_TREE,
                    worker_pool_root=self.worker,
                    expected_worker_pool_sha=WORKER_SHA,
                    expected_worker_pool_tree=WORKER_TREE,
                    correlation_id="physical-preflight-003",
                    route=self.route,
                    checkout_verifier=self.verifier,
                    contract_loader=lambda _checkout: p.WorkerTransportContract(
                        FakeConfig, FakeTransport,
                    ),
                    credential_runner=mutating,
                )
            self.assertEqual(os.environ.get(marker), original)
        finally:
            if original is None:
                os.environ.pop(marker, None)
            else:
                os.environ[marker] = original

    def test_checkout_uses_physical_identity_not_lexical_alias(self) -> None:
        alias = self.root / "lexically-different-alias"

        def git_runner(_root: Path, arguments: tuple[str, ...]) -> str:
            if arguments == ("rev-parse", "--show-toplevel"):
                return str(alias)
            if arguments == ("rev-parse", "--verify", "HEAD"):
                return WORKER_SHA
            if arguments == ("rev-parse", "--verify", "HEAD^{tree}"):
                return WORKER_TREE
            if arguments[0] == "status":
                return ""
            if arguments == ("ls-files", "-v", "-z"):
                return "H app/native_one_shot.py\0H app/s3_git_bundle_artifact.py\0"
            self.fail(f"unexpected git arguments: {arguments}")

        with patch.object(p, "_same_physical_path", return_value=True):
            observed = p._verify_checkout(
                self.worker,
                WORKER_SHA,
                WORKER_TREE,
                "worker_pool",
                git_runner=git_runner,
            )
        self.assertEqual(observed.root, self.worker.resolve())

    def test_dirty_or_wrong_checkout_is_rejected(self) -> None:
        def dirty_git(_root: Path, arguments: tuple[str, ...]) -> str:
            if arguments == ("rev-parse", "--show-toplevel"):
                return str(self.worker)
            if arguments == ("rev-parse", "--verify", "HEAD"):
                return WORKER_SHA
            if arguments == ("rev-parse", "--verify", "HEAD^{tree}"):
                return WORKER_TREE
            return "?? unexpected.txt"

        with self.assertRaisesRegex(
            p.PhysicalPreflightError, "worker_pool_checkout_invalid",
        ):
            p._verify_checkout(
                self.worker,
                WORKER_SHA,
                WORKER_TREE,
                "worker_pool",
                git_runner=dirty_git,
            )

    def test_real_git_checkout_and_ignored_control(self) -> None:
        repository = self.root / "real-worker"
        repository.mkdir()

        def git(*arguments: str) -> str:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=repository,
                check=True,
                text=True,
                capture_output=True,
                timeout=20,
            )
            return completed.stdout.strip()

        git("init", "--quiet")
        (repository / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (repository / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
        git("add", ".gitignore", "module.py")
        git(
            "-c", "user.name=Test",
            "-c", "user.email=test@example.invalid",
            "commit", "--quiet", "-m", "fixture",
        )
        head = git("rev-parse", "HEAD")
        tree = git("rev-parse", "HEAD^{tree}")
        identity = p._verify_checkout(repository, head, tree, "worker_pool")
        self.assertEqual(identity.head, head)
        ignored = repository / "__pycache__"
        ignored.mkdir()
        (ignored / "module.pyc").write_bytes(b"synthetic")
        with self.assertRaisesRegex(
            p.PhysicalPreflightError, "worker_pool_checkout_invalid",
        ):
            p._verify_checkout(repository, head, tree, "worker_pool")

    def test_git_for_windows_autocrlf_checkout_is_clean_without_system_config(
        self,
    ) -> None:
        repository = self.root / "windows-autocrlf-worker"
        repository.mkdir()

        def git(*arguments: str) -> str:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=repository,
                check=True,
                text=True,
                capture_output=True,
                timeout=20,
            )
            return completed.stdout.strip()

        git("init", "--quiet")
        (repository / ".gitignore").write_bytes(b"__pycache__/\r\n")
        (repository / "module.py").write_bytes(b"VALUE = 1\r\n")
        git("-c", "core.autocrlf=true", "add", ".gitignore", "module.py")
        git(
            "-c", "core.autocrlf=true",
            "-c", "user.name=Test",
            "-c", "user.email=test@example.invalid",
            "commit", "--quiet", "-m", "windows autocrlf fixture",
        )
        head = git("rev-parse", "HEAD")
        tree = git("rev-parse", "HEAD^{tree}")
        status_arguments = (
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
            "-z",
        )

        # This is the false dirty result produced by the old verifier after it
        # hid Git for Windows' system-level core.autocrlf=true.
        self.assertIn(
            "module.py",
            p._git_output(
                repository,
                status_arguments,
                platform_name="posix",
            ),
        )

        def windows_git_runner(root: Path, arguments: tuple[str, ...]) -> str:
            return p._git_output(root, arguments, platform_name="nt")

        identity = p._verify_checkout(
            repository,
            head,
            tree,
            "worker_pool",
            git_runner=windows_git_runner,
        )
        self.assertEqual(identity.head, head)

        (repository / "module.py").write_bytes(b"VALUE = 12345\r\n")
        with self.assertRaisesRegex(
            p.PhysicalPreflightError, "worker_pool_checkout_invalid",
        ):
            p._verify_checkout(
                repository,
                head,
                tree,
                "worker_pool",
                git_runner=windows_git_runner,
            )
        (repository / "module.py").write_bytes(b"VALUE = 1\r\n")

        ignored = repository / "__pycache__"
        ignored.mkdir()
        (ignored / "module.pyc").write_bytes(b"synthetic")
        with self.assertRaisesRegex(
            p.PhysicalPreflightError, "worker_pool_checkout_invalid",
        ):
            p._verify_checkout(
                repository,
                head,
                tree,
                "worker_pool",
                git_runner=windows_git_runner,
            )

    def test_ignored_content_or_special_index_flags_are_rejected(self) -> None:
        def controlled_git(_root: Path, arguments: tuple[str, ...]) -> str:
            if arguments == ("rev-parse", "--show-toplevel"):
                return str(self.worker)
            if arguments == ("rev-parse", "--verify", "HEAD"):
                return WORKER_SHA
            if arguments == ("rev-parse", "--verify", "HEAD^{tree}"):
                return WORKER_TREE
            if arguments[0] == "status":
                return getattr(controlled_git, "status", "")
            if arguments == ("ls-files", "-v", "-z"):
                return getattr(controlled_git, "index", "H app/module.py\0")
            self.fail(f"unexpected git arguments: {arguments}")

        cases = (
            ("!! app/__pycache__/module.pyc\0", "H app/module.py\0"),
            ("", "S app/module.py\0"),
            ("", "h app/module.py\0"),
        )
        for status, index in cases:
            controlled_git.status = status  # type: ignore[attr-defined]
            controlled_git.index = index  # type: ignore[attr-defined]
            with self.subTest(status=status, index=index), self.assertRaisesRegex(
                p.PhysicalPreflightError, "worker_pool_checkout_invalid",
            ):
                p._verify_checkout(
                    self.worker,
                    WORKER_SHA,
                    WORKER_TREE,
                    "worker_pool",
                    git_runner=controlled_git,
                )

    def test_git_subprocess_discards_untrusted_git_environment(self) -> None:
        captured: dict[str, object] = {}

        class Done:
            returncode = 0
            stdout = "ok\n"

        def run(argv: list[str], **kwargs: object) -> Done:
            captured["argv"] = argv
            captured["environment"] = kwargs["env"]
            return Done()

        with patch.dict(
            os.environ,
            {
                "GIT_COMMON_DIR": str(self.root / "malicious"),
                "GIT_EXEC_PATH": str(self.root / "untrusted-exec"),
                "GIT_CONFIG_COUNT": "1",
            },
        ), patch.object(p.subprocess, "run", side_effect=run):
            self.assertEqual(p._git_output(self.worker, ("status",)), "ok")
        environment = captured["environment"]
        self.assertNotIn("GIT_COMMON_DIR", environment)
        self.assertNotIn("GIT_EXEC_PATH", environment)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertIn("core.fsmonitor=false", captured["argv"])
        expected_default_autocrlf = "true" if os.name == "nt" else "false"
        self.assertIn(
            f"core.autocrlf={expected_default_autocrlf}",
            captured["argv"],
        )

        for platform_name, expected_autocrlf in (
            ("nt", "true"),
            ("posix", "false"),
        ):
            with self.subTest(platform_name=platform_name), patch.object(
                p.subprocess,
                "run",
                side_effect=run,
            ):
                self.assertEqual(
                    p._git_output(
                        self.worker,
                        ("status",),
                        platform_name=platform_name,
                    ),
                    "ok",
                )
                self.assertIn(
                    f"core.autocrlf={expected_autocrlf}",
                    captured["argv"],
                )

    def test_worker_contract_must_resolve_to_verified_checkout(self) -> None:
        app = self.worker / "app"
        app.mkdir()
        module_path = app / "s3_git_bundle_artifact.py"
        native_path = app / "native_one_shot.py"
        module_path.write_text("# synthetic\n", encoding="utf-8")
        native_path.write_text("# synthetic\n", encoding="utf-8")
        synthetic = types.SimpleNamespace(
            __file__=str(module_path),
            S3ArtifactConfig=FakeConfig,
            S3GitBundleArtifactTransport=FakeTransport,
        )
        identity = p.CheckoutIdentity(self.worker, WORKER_SHA, WORKER_TREE)
        with patch.object(p.importlib, "import_module", return_value=synthetic):
            contract = p._load_worker_transport(identity)
        self.assertIs(contract.config_type, FakeConfig)
        self.assertIs(contract.transport_type, FakeTransport)

    def test_cli_failure_evidence_never_contains_exception_or_route(self) -> None:
        output = self.root / "evidence.json"
        stderr = io.StringIO()
        arguments = [
            "--expected-runtime-sha", RUNTIME_SHA,
            "--expected-runtime-tree", RUNTIME_TREE,
            "--worker-pool-root", str(self.worker),
            "--expected-worker-pool-sha", WORKER_SHA,
            "--expected-worker-pool-tree", WORKER_TREE,
            "--correlation-id", "physical-preflight-004",
            "--bucket", self.route.bucket,
            "--region", self.route.region,
            "--endpoint-url", self.route.endpoint_url,
            "--key-prefix", self.route.key_prefix,
            "--output", str(output),
        ]
        with patch.object(p, "execute_preflight", side_effect=RuntimeError(SECRET)):
            with redirect_stderr(stderr):
                code = p.main(arguments)
        rendered = output.read_text(encoding="ascii") + stderr.getvalue()
        self.assertEqual(code, 2)
        self.assertNotIn(SECRET, rendered)
        self.assertNotIn(self.route.bucket, rendered)
        self.assertNotIn(self.route.endpoint_url, rendered)
        self.assertIn("s3_preflight_failed", rendered)

    def test_evidence_inside_repository_is_rejected(self) -> None:
        path = p.REPOSITORY_ROOT / "forbidden-evidence.json"
        with self.assertRaisesRegex(
            p.PhysicalPreflightError, "evidence_path_invalid",
        ):
            p._write_evidence(path, {"result": "synthetic"})

    def test_evidence_inside_worker_checkout_is_rejected(self) -> None:
        path = self.worker / "forbidden-evidence.json"
        with self.assertRaisesRegex(
            p.PhysicalPreflightError, "evidence_path_invalid",
        ):
            p._write_evidence(
                path,
                {"result": "synthetic"},
                additional_forbidden_roots=(self.worker,),
            )

    def test_cli_rejects_worker_evidence_path_before_network_effect(self) -> None:
        output = self.worker / "evidence.json"
        arguments = [
            "--expected-runtime-sha", RUNTIME_SHA,
            "--expected-runtime-tree", RUNTIME_TREE,
            "--worker-pool-root", str(self.worker),
            "--expected-worker-pool-sha", WORKER_SHA,
            "--expected-worker-pool-tree", WORKER_TREE,
            "--correlation-id", "physical-preflight-path-control",
            "--bucket", self.route.bucket,
            "--region", self.route.region,
            "--endpoint-url", self.route.endpoint_url,
            "--key-prefix", self.route.key_prefix,
            "--output", str(output),
        ]
        with patch.object(p, "execute_preflight") as execute:
            code = p.main(arguments)
        self.assertEqual(code, 2)
        execute.assert_not_called()
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
