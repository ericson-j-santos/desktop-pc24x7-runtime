"""Offline security tests for the Desktop Worker Pool S3 credential store."""
from __future__ import annotations

import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import desktop_worker_s3_credentials as m


ACCESS_KEY = "TEST_ONLY_ACCESS_KEY_ID_0123456789"
SECRET_KEY = "TEST-ONLY-NOT-A-CREDENTIAL-MUST-NOT-APPEAR-0123456789"


def credential_json(*, secret: str = SECRET_KEY) -> bytes:
    return json.dumps({
        "schema_version": "1.0.0",
        "aws_access_key_id": ACCESS_KEY,
        "aws_secret_access_key": secret,
    }, sort_keys=True).encode("utf-8")


def toy_protect(data: bytes) -> bytes:
    return b"TOY-DPAPI:" + bytes(value ^ 0xA5 for value in data)


def toy_unprotect(data: bytes) -> bytes:
    if not data.startswith(b"TOY-DPAPI:"):
        raise ValueError("invalid synthetic ciphertext")
    return bytes(value ^ 0xA5 for value in data[len(b"TOY-DPAPI:"):])


class FakeAcl:
    def __init__(self) -> None:
        self.secured: list[Path] = []
        self.checked: list[Path] = []
        self.fail_check = False

    def secure(self, path: Path) -> None:
        if not path.exists():
            raise OSError("missing path")
        self.secured.append(path)

    def check(self, path: Path) -> None:
        if self.fail_check or not path.exists():
            raise OSError("untrusted ACL")
        self.checked.append(path)


class TtyBytesIO(io.BytesIO):
    def isatty(self) -> bool:
        return True


class FakeClient:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class DesktopWorkerS3CredentialsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "protected" / "s3-credential-v1.json"
        self.credential = m.S3Credential(ACCESS_KEY, SECRET_KEY)

    def install(self, *, acl: FakeAcl | None = None) -> FakeAcl:
        active_acl = FakeAcl() if acl is None else acl
        result = m._install_credential_core(
            self.credential,
            self.path,
            acl=active_acl,
            protect=toy_protect,
            unprotect=toy_unprotect,
        )
        self.assertTrue(result["ok"])
        return active_acl

    def test_stdin_accepts_exact_schema_and_repr_is_redacted(self) -> None:
        credential = m.read_credential_stdin(io.BytesIO(credential_json()))
        self.assertEqual(credential.access_key_id, ACCESS_KEY)
        self.assertEqual(credential.secret_access_key, SECRET_KEY)
        self.assertEqual(repr(credential), "S3Credential(<redacted>)")
        self.assertNotIn(SECRET_KEY, repr(credential))

    def test_host_and_dpapi_direction_are_explicit(self) -> None:
        with patch.object(m.os, "name", "nt"), patch.object(
            m.socket, "gethostname", return_value=m.EXPECTED_HOST,
        ):
            m.require_windows_host()
        with patch.object(m.os, "name", "nt"), patch.object(
            m.socket, "gethostname", return_value="UNTRUSTED-HOST",
        ):
            with self.assertRaisesRegex(
                m.CredentialBootstrapError, "fixed_windows_host_required",
            ):
                m.require_windows_host()

        directions: list[bool] = []

        def fake_dpapi(data: bytes, *, encrypt: bool) -> bytes:
            directions.append(encrypt)
            return data

        with patch.object(m, "dpapi", side_effect=fake_dpapi):
            self.assertEqual(m._protect_current_user(b"plain"), b"plain")
            self.assertEqual(m._unprotect_current_user(b"cipher"), b"cipher")
        self.assertEqual(directions, [True, False])

    def test_stdin_rejects_tty_duplicate_unknown_and_oversize(self) -> None:
        cases = [
            TtyBytesIO(credential_json()),
            io.BytesIO(
                b'{"schema_version":"1.0.0","schema_version":"1.0.0",'
                b'"aws_access_key_id":"abc","aws_secret_access_key":"12345678"}'
            ),
            io.BytesIO(json.dumps({
                "schema_version": "1.0.0",
                "aws_access_key_id": ACCESS_KEY,
                "aws_secret_access_key": SECRET_KEY,
                "unexpected": True,
            }).encode()),
            io.BytesIO(b"x" * (m.MAX_INPUT_BYTES + 1)),
        ]
        for stream in cases:
            with self.subTest(stream=type(stream).__name__), self.assertRaises(
                m.CredentialBootstrapError,
            ):
                m.read_credential_stdin(stream)

    def test_roundtrip_is_atomic_private_and_contains_no_plaintext(self) -> None:
        acl = self.install()
        self.assertTrue(self.path.is_file())
        stored = self.path.read_bytes()
        self.assertNotIn(ACCESS_KEY.encode(), stored)
        self.assertNotIn(SECRET_KEY.encode(), stored)
        self.assertTrue(
            any(
                path.exists() and os.path.samefile(self.path.parent, path)
                for path in acl.secured
            ),
            "the physical credential directory must receive the private ACL",
        )
        self.assertTrue(
            any(
                path.exists() and os.path.samefile(self.path, path)
                for path in acl.checked
            ),
            "the physical credential file must receive ACL readback",
        )
        self.assertEqual(
            list(self.path.parent.glob("*.pending")),
            [],
        )
        loaded = m._load_credential_core(
            self.path, acl=acl, unprotect=toy_unprotect,
        )
        self.assertEqual(loaded, self.credential)

    def test_existing_store_is_never_overwritten(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(b"existing-protected-value")
        before = self.path.read_bytes()
        with self.assertRaisesRegex(
            m.CredentialBootstrapError, "credential_already_installed",
        ):
            self.install()
        self.assertEqual(self.path.read_bytes(), before)

    def test_publish_race_does_not_replace_concurrent_target(self) -> None:
        concurrent = b"concurrent-protected-value"

        def lose_race(_source: object, destination: object) -> None:
            Path(destination).write_bytes(concurrent)
            raise FileExistsError("target exists")

        with patch.object(m.os, "rename", side_effect=lose_race):
            with self.assertRaisesRegex(
                m.CredentialBootstrapError, "credential_write_failed",
            ):
                self.install()
        self.assertEqual(self.path.read_bytes(), concurrent)

    def test_protection_failures_are_bounded_and_sanitized(self) -> None:
        def leaking_protect(_plaintext: bytes) -> bytes:
            raise RuntimeError(SECRET_KEY)

        with self.assertRaisesRegex(
            m.CredentialBootstrapError, "credential_protection_failed",
        ) as caught:
            m._install_credential_core(
                self.credential,
                self.path,
                acl=FakeAcl(),
                protect=leaking_protect,
                unprotect=toy_unprotect,
            )
        self.assertNotIn(SECRET_KEY, str(caught.exception))
        self.assertFalse(self.path.exists())

        protected = m._outer_envelope(toy_protect(m._credential_bytes(self.credential)))
        invalid_unprotectors = [
            lambda _ciphertext: bytearray(b"not-bytes"),
            lambda _ciphertext: (_ for _ in ()).throw(RuntimeError(SECRET_KEY)),
        ]
        for unprotect in invalid_unprotectors:
            with self.subTest(unprotect=unprotect), self.assertRaisesRegex(
                m.CredentialBootstrapError, "credential_protection_failed",
            ) as unprotect_caught:
                m._unprotect_credential(protected, unprotect=unprotect)
            self.assertNotIn(SECRET_KEY, str(unprotect_caught.exception))

    def test_tampered_cipher_digest_fails_closed(self) -> None:
        acl = self.install()
        envelope = json.loads(self.path.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(envelope["ciphertext_base64"]))
        ciphertext[-1] ^= 0x01
        envelope["ciphertext_base64"] = base64.b64encode(ciphertext).decode("ascii")
        self.path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaisesRegex(m.CredentialBootstrapError, "credential_cipher_invalid"):
            m._load_credential_core(self.path, acl=acl, unprotect=toy_unprotect)

    def test_tampered_cipher_with_recomputed_digest_still_fails(self) -> None:
        acl = self.install()
        envelope = json.loads(self.path.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(envelope["ciphertext_base64"]))
        ciphertext[0] ^= 0x01
        raw = bytes(ciphertext)
        envelope["ciphertext_base64"] = base64.b64encode(raw).decode("ascii")
        envelope["ciphertext_sha256"] = hashlib.sha256(raw).hexdigest()
        self.path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaisesRegex(
            m.CredentialBootstrapError, "credential_protection_failed",
        ):
            m._load_credential_core(self.path, acl=acl, unprotect=toy_unprotect)

    def test_untrusted_acl_blocks_before_decryption(self) -> None:
        acl = self.install()
        acl.fail_check = True
        called = False

        def forbidden(_data: bytes) -> bytes:
            nonlocal called
            called = True
            raise AssertionError("must not decrypt")

        with self.assertRaisesRegex(m.CredentialBootstrapError, "credential_acl_failed"):
            m._load_credential_core(self.path, acl=acl, unprotect=forbidden)
        self.assertFalse(called)

    def test_repository_destination_is_rejected(self) -> None:
        path = m.REPOSITORY_ROOT / "s3-credential-v1.json"
        with self.assertRaisesRegex(
            m.CredentialBootstrapError, "credential_path_inside_repository",
        ):
            m._install_credential_core(
                self.credential,
                path,
                acl=FakeAcl(),
                protect=toy_protect,
                unprotect=toy_unprotect,
            )

    @unittest.skipIf(os.name == "nt", "POSIX-only fail-closed control")
    def test_public_entrypoints_fail_closed_outside_windows(self) -> None:
        route = m.S3Route(
            bucket="private-artifacts",
            region="us-east-2",
            endpoint_url="https://storage.example.invalid",
            key_prefix="worker/checkpoints",
        )
        with self.assertRaisesRegex(m.CredentialBootstrapError, "fixed_windows_host_required"):
            m.credential_status()
        with self.assertRaisesRegex(m.CredentialBootstrapError, "fixed_windows_host_required"):
            m.run_with_s3_client(route, lambda _client, _route: None)

        class ForbiddenInput(io.BytesIO):
            def read(self, _size: int = -1) -> bytes:
                raise AssertionError("stdin must not be read outside the fixed Windows host")

        output = io.StringIO()
        with redirect_stdout(output):
            code = m.main(
                ["install", "--confirm", m.INSTALL_CONFIRM],
                stdin=ForbiddenInput(credential_json()),
            )
        self.assertEqual(code, 2)
        self.assertIn("fixed_windows_host_required", output.getvalue())
        self.assertNotIn(SECRET_KEY, output.getvalue())

    def test_explicit_client_callback_never_mutates_aws_environment(self) -> None:
        route = m.S3Route(
            bucket="private-artifacts",
            region="us-east-2",
            endpoint_url="https://storage.example.invalid",
            key_prefix="worker/checkpoints",
        )
        client = FakeClient()
        observed: dict[str, object] = {}

        def factory(actual_route: m.S3Route, credential: m.S3Credential) -> FakeClient:
            observed["route"] = actual_route
            observed["credential"] = credential
            return client

        before = {key: value for key, value in os.environ.items() if key.startswith("AWS_")}
        result = m._run_with_s3_client_core(
            route,
            lambda actual_client, actual_route: (
                actual_client is client,
                actual_route == route,
            ),
            credential_loader=lambda: self.credential,
            client_factory=factory,
        )
        after = {key: value for key, value in os.environ.items() if key.startswith("AWS_")}
        self.assertEqual(result, (True, True))
        self.assertEqual(observed["route"], route)
        self.assertEqual(observed["credential"], self.credential)
        self.assertEqual(after, before)
        self.assertTrue(client.closed)

    def test_callback_failure_is_sanitized_and_closes_client(self) -> None:
        route = m.S3Route(
            bucket="private-artifacts",
            region="us-east-2",
            endpoint_url="https://storage.example.invalid",
            key_prefix="worker/checkpoints",
        )
        client = FakeClient()

        def fail(_client: object, _route: m.S3Route) -> None:
            raise RuntimeError(SECRET_KEY)

        with self.assertRaisesRegex(m.CredentialBootstrapError, "s3_callback_failed") as caught:
            m._run_with_s3_client_core(
                route,
                fail,
                credential_loader=lambda: self.credential,
                client_factory=lambda _route, _credential: client,
            )
        self.assertNotIn(SECRET_KEY, str(caught.exception))
        self.assertTrue(client.closed)

    def test_boto_factory_passes_explicit_credentials_without_env_mutation(self) -> None:
        route = m.S3Route(
            bucket="private-artifacts",
            region="us-east-2",
            endpoint_url="https://storage.example.invalid",
            key_prefix="worker/checkpoints",
        )
        captured: dict[str, object] = {}
        fake_boto3 = types.ModuleType("boto3")

        def client(service: str, **kwargs: object) -> FakeClient:
            captured["service"] = service
            captured.update(kwargs)
            return FakeClient()

        fake_boto3.client = client  # type: ignore[attr-defined]
        fake_botocore = types.ModuleType("botocore")
        fake_config_module = types.ModuleType("botocore.config")

        class Config:
            def __init__(self, **kwargs: object) -> None:
                self.kwargs = kwargs

        fake_config_module.Config = Config  # type: ignore[attr-defined]
        modules = {
            "boto3": fake_boto3,
            "botocore": fake_botocore,
            "botocore.config": fake_config_module,
        }
        before = dict(os.environ)
        with patch.dict(sys.modules, modules):
            created = m._default_client_factory(route, self.credential)
        self.assertIsInstance(created, FakeClient)
        self.assertEqual(captured["service"], "s3")
        self.assertEqual(captured["aws_access_key_id"], ACCESS_KEY)
        self.assertEqual(captured["aws_secret_access_key"], SECRET_KEY)
        self.assertEqual(captured["endpoint_url"], route.endpoint_url)
        self.assertTrue(captured["verify"])
        config = captured["config"]
        self.assertEqual(config.kwargs["signature_version"], "s3v4")
        self.assertEqual(config.kwargs["s3"], {"addressing_style": "path"})
        self.assertEqual(
            config.kwargs["retries"], {"mode": "standard", "total_max_attempts": 1},
        )
        self.assertTrue(config.kwargs["ignore_configured_endpoint_urls"])
        self.assertEqual(dict(os.environ), before)

    def test_status_and_cli_failure_never_emit_secret(self) -> None:
        acl = self.install()
        credential = m._load_credential_core(
            self.path, acl=acl, unprotect=toy_unprotect,
        )
        credential = None
        status = m._safe_status("credential_verified_for_current_process_identity")
        rendered = json.dumps(status, sort_keys=True)
        self.assertNotIn(ACCESS_KEY, rendered)
        self.assertNotIn(SECRET_KEY, rendered)
        output = io.StringIO()
        with patch.object(m, "require_windows_host", side_effect=RuntimeError(SECRET_KEY)):
            with redirect_stdout(output):
                code = m.main(["status"])
        self.assertEqual(code, 3)
        self.assertNotIn(ACCESS_KEY, output.getvalue())
        self.assertNotIn(SECRET_KEY, output.getvalue())
        self.assertIn("credential_operation_failed", output.getvalue())

    def test_invalid_routes_are_rejected(self) -> None:
        invalid = [
            ("private.-artifacts", "us-east-2", "https://example.invalid", "x/y"),
            ("private-.artifacts", "us-east-2", "https://example.invalid", "x/y"),
            ("private-artifacts", "us-east-2", "http://storage.example.invalid", "x/y"),
            ("private-artifacts", "us-east-2", "https://user:secret@example.invalid", "x/y"),
            ("private-artifacts", "us-east-2", "https://example.invalid/path", "x/y"),
            ("private-artifacts", "us-east-2", "https://example.invalid", "x/../y"),
        ]
        for bucket, region, endpoint, prefix in invalid:
            with self.subTest(endpoint=endpoint, prefix=prefix), self.assertRaises(
                m.CredentialBootstrapError,
            ):
                m.S3Route(bucket, region, endpoint, prefix)


if __name__ == "__main__":
    unittest.main()
