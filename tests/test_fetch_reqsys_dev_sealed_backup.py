"""Contracts for a pinned ciphertext transfer; no credentials or network needed."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts/fetch_reqsys_dev_sealed_backup.py"
SPEC = importlib.util.spec_from_file_location("sealed_backup_fetch", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
fetcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetcher)
RUN_ID = 123456
ARTIFACT_ID = 789012
SHA = "a" * 40
NOW = 1_800_000_000


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def envelope_object():
    return {
        "header": {
            "schema": fetcher.CIPHER_SCHEMA,
            "source_host": "Noteri", "target_host": fetcher.TARGET_HOST,
            "snapshot_id": fetcher.SNAPSHOT_ID, "sqlite_sha256": fetcher.SQLITE_SHA256,
            "sqlite_bytes": fetcher.SQLITE_BYTES, "source_run_id": RUN_ID,
            "source_sha": SHA, "recipient_sha256": "b" * 64,
            "created_at": NOW, "expires_at": NOW + 3600,
        },
        "nonce_b64": base64.b64encode(b"n" * 12).decode(),
        "sealed_key_b64": base64.b64encode(b"k" * 384).decode(),
        "ciphertext_b64": base64.b64encode(b"c" * (fetcher.SQLITE_BYTES + 16)).decode(),
    }


def zip_bytes(envelope, name="envelope.json", extra=False, mode=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if mode is None:
            archive.writestr(name, envelope)
        else:
            entry = zipfile.ZipInfo(name)
            entry.external_attr = mode << 16
            archive.writestr(entry, envelope)
        if extra:
            archive.writestr("extra.txt", b"blocked")
    return buffer.getvalue()


class FakeGh:
    def __init__(self, envelope=None):
        self.envelope = json_bytes(envelope or envelope_object())
        self.archive = zip_bytes(self.envelope)
        self.calls = []
        self.owner_ok = True
        self.run = {
            "id": RUN_ID, "head_sha": SHA, "head_branch": fetcher.SOURCE_BRANCH,
            "path": fetcher.SOURCE_WORKFLOW, "event": "push", "status": "completed",
            "conclusion": "success", "repository": {"full_name": fetcher.SOURCE_REPO},
            "head_repository": {"full_name": fetcher.SOURCE_REPO},
        }
        self.jobs = {
            "total_count": 1,
            "jobs": [{
                "name": fetcher.SOURCE_JOB, "run_id": RUN_ID, "head_sha": SHA,
                "status": "completed", "conclusion": "success", "runner_name": "Noteri",
                "runner_id": 21, "labels": sorted(fetcher.SOURCE_LABELS),
            }],
        }
        self.artifact = {
            "id": ARTIFACT_ID, "name": f"reqsys-dev-backup-restic-{RUN_ID}",
            "expired": False, "size_in_bytes": len(self.archive),
            "digest": f"sha256:{fetcher.digest(self.archive)}",
            "workflow_run": {
                "id": RUN_ID, "head_sha": SHA, "head_branch": fetcher.SOURCE_BRANCH,
            },
        }

    def verify_owner(self):
        self.calls.append(("owner", False))
        if not self.owner_ok:
            raise fetcher.FetchError("existing_local_gh_owner_unverified")

    def get(self, endpoint, binary=False):
        self.calls.append((endpoint, binary))
        if endpoint.endswith("/zip"):
            return self.archive
        if "/jobs?" in endpoint:
            return json_bytes(self.jobs)
        if "/artifacts/" in endpoint:
            return json_bytes(self.artifact)
        return json_bytes(self.run)


class ArtifactTransferTests(unittest.TestCase):
    def perform(self, gh, destination, artifact_hash=None, envelope_hash=None):
        return fetcher.fetch(
            gh, RUN_ID, SHA, ARTIFACT_ID, artifact_hash or fetcher.digest(gh.archive),
            envelope_hash or fetcher.digest(gh.envelope), destination, NOW,
        )

    def test_verified_ciphertext_and_idempotent_preservation(self):
        gh = FakeGh()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "envelope.json"
            first = self.perform(gh, output)
            modified = output.stat().st_mtime_ns
            second = self.perform(gh, output)
            self.assertTrue(first["file_created"])
            self.assertFalse(second["file_created"])
            self.assertEqual(output.read_bytes(), gh.envelope)
            self.assertEqual(output.stat().st_mtime_ns, modified)
            self.assertEqual(list(Path(temp).iterdir()), [output])
            self.assertTrue(first["ciphertext_only"])
            self.assertFalse(first["new_credentials_created"])
            self.assertFalse(first["services_activated"])
            prefix = f"repos/{fetcher.SOURCE_REPO}/actions"
            self.assertEqual(gh.calls[:5], [
                ("owner", False), (f"{prefix}/runs/{RUN_ID}", False),
                (f"{prefix}/runs/{RUN_ID}/jobs?per_page=100", False),
                (f"{prefix}/artifacts/{ARTIFACT_ID}", False),
                (f"{prefix}/artifacts/{ARTIFACT_ID}/zip", True),
            ])

    def test_existing_mismatched_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "envelope.json"
            output.write_bytes(b"preserved")
            with self.assertRaisesRegex(fetcher.FetchError, "existing_envelope_conflict"):
                self.perform(FakeGh(), output)
            self.assertEqual(output.read_bytes(), b"preserved")

    def test_wrong_owner_blocks_before_any_repository_request(self):
        gh = FakeGh()
        gh.owner_ok = False
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "envelope.json"
            with self.assertRaisesRegex(fetcher.FetchError, "owner_unverified"):
                self.perform(gh, output)
            self.assertEqual(gh.calls, [("owner", False)])
            self.assertFalse(output.exists())

    def test_wrong_source_binding_blocks_before_download(self):
        mutations = [
            ("run", "head_sha", "d" * 40), ("run", "head_branch", "main"),
            ("run", "event", "pull_request"), ("run", "conclusion", "failure"),
            ("run", "path", ".github/workflows/other.yml"),
            ("artifact", "expired", True), ("artifact", "name", "plaintext-backup"),
            ("artifact", "digest", "sha256:" + "0" * 64),
        ]
        for target, key, value in mutations:
            with self.subTest(target=target, key=key):
                gh = FakeGh()
                getattr(gh, target)[key] = value
                with tempfile.TemporaryDirectory() as temp:
                    output = Path(temp) / "envelope.json"
                    with self.assertRaises(fetcher.FetchError):
                        self.perform(gh, output)
                    self.assertFalse(any(binary for _, binary in gh.calls))
                    self.assertFalse(output.exists())

    def test_other_runner_or_failed_backup_job_blocks(self):
        for key, value in (
            ("runner_name", "other"), ("runner_id", None),
            ("labels", ["self-hosted", "Windows", "X64"]),
            ("conclusion", "failure"), ("head_sha", "d" * 40),
        ):
            with self.subTest(key=key):
                gh = FakeGh()
                gh.jobs["jobs"][0][key] = value
                with tempfile.TemporaryDirectory() as temp:
                    output = Path(temp) / "envelope.json"
                    with self.assertRaisesRegex(fetcher.FetchError, "source_backup_job_unverified"):
                        self.perform(gh, output)
                    self.assertFalse(any(binary for _, binary in gh.calls))

    def test_archive_and_envelope_hash_pins_checked_before_write(self):
        for field in ("artifact", "envelope"):
            gh = FakeGh()
            with tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / "envelope.json"
                kwargs = {field + "_hash": "0" * 64}
                with self.assertRaises(fetcher.FetchError):
                    self.perform(gh, output, **kwargs)
                self.assertFalse(output.exists())

    def test_only_one_regular_envelope_zip_member(self):
        content = json_bytes(envelope_object())
        archives = (
            zip_bytes(content, "../envelope.json"),
            zip_bytes(content, extra=True),
            zip_bytes(content, mode=stat.S_IFLNK | 0o777),
            b"SQLite format 3\x00",
        )
        for archive in archives:
            with self.subTest(size=len(archive)):
                with self.assertRaises(fetcher.FetchError):
                    fetcher.extract_envelope(archive)

    def test_archive_and_expansion_are_bounded(self):
        with self.assertRaises(fetcher.FetchError):
            fetcher.extract_envelope(b"x" * (fetcher.MAX_BYTES + 1))
        oversized = zip_bytes(b"x" * (fetcher.MAX_BYTES + 1))
        with self.assertRaises(fetcher.FetchError):
            fetcher.extract_envelope(oversized)

    def test_cipher_schema_expiry_and_plaintext_rejected(self):
        base = envelope_object()
        invalid = []
        item = copy.deepcopy(base)
        item["header"]["expires_at"] = NOW
        invalid.append(item)
        item = copy.deepcopy(base)
        item["header"]["source_sha"] = "0" * 40
        invalid.append(item)
        item = copy.deepcopy(base)
        item["plaintext_sqlite"] = "blocked"
        invalid.append(item)
        item = copy.deepcopy(base)
        item["nonce_b64"] = "invalid"
        invalid.append(item)
        item = copy.deepcopy(base)
        plaintext = b"SQLite format 3\x00" + b"x" * (fetcher.SQLITE_BYTES + 16 - 16)
        item["ciphertext_b64"] = base64.b64encode(plaintext).decode()
        invalid.append(item)
        for item in invalid:
            with self.assertRaises(fetcher.FetchError):
                fetcher.validate_envelope(json_bytes(item), RUN_ID, SHA, NOW)
        with self.assertRaises(fetcher.FetchError):
            fetcher.parse_json(b'{"header":{},"header":{}}')
        with self.assertRaises(fetcher.FetchError):
            fetcher.parse_json(b'{"value":NaN}')

    def test_reparse_or_symlink_output_rejected(self):
        if os.name == "nt":
            self.skipTest("Symlink requires Windows developer privilege; host lstat path check is shared.")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            existing = root / "existing"
            existing.write_bytes(b"preserved")
            destination = root / "envelope.json"
            destination.symlink_to(existing)
            with self.assertRaisesRegex(fetcher.FetchError, "output_reparse_point_rejected"):
                fetcher.preserve_write(destination, json_bytes(envelope_object()))
            self.assertEqual(existing.read_bytes(), b"preserved")

    def test_runner_temp_output_fixed_and_no_arbitrary_path_cli(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": temp}):
                self.assertEqual(fetcher.output_path(),
                                 Path(temp) / "dev-backup-input/envelope.json")
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            code = fetcher.main(["--url", "https://example.invalid/private"])
        self.assertEqual(code, 2)
        self.assertNotIn("example", output.getvalue())
        self.assertIn("invalid_cli", output.getvalue())

    def test_inherited_workflow_tokens_never_used(self):
        keys = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
        with mock.patch.dict(os.environ, {key: "redacted" for key in keys}):
            env = fetcher.local_gh_env()
        self.assertTrue(all(key not in env for key in keys))
        self.assertEqual(env["GH_HOST"], "github.com")
        self.assertEqual(env["GH_PROMPT_DISABLED"], "1")

    def test_gh_get_uses_allowlist_and_no_token_export(self):
        with mock.patch.object(fetcher, "find_gh", return_value="gh.exe"):
            client = fetcher.ExistingOwnerGh(RUN_ID, ARTIFACT_ID)
        with mock.patch.object(fetcher, "capture_bounded") as capture:
            capture.return_value = b"ericson-j-santos\n"
            client.verify_owner()
            command = capture.call_args.args[0]
            self.assertEqual(command, [
                "gh.exe", "api", "--hostname", "github.com", "--method", "GET",
                "user", "--jq", ".login",
            ])
            with self.assertRaisesRegex(fetcher.FetchError, "endpoint_not_allowed"):
                client.get("repos/other/other/actions/artifacts/12/zip", binary=True)
            self.assertEqual(capture.call_count, 1)
            capture.return_value = b"{}"
            client.get(f"repos/{fetcher.SOURCE_REPO}/actions/runs/{RUN_ID}")
            command = capture.call_args.args[0]
            self.assertNotIn("--output", command)
            self.assertNotIn("auth", command)
            self.assertNotIn("token", command)


class FakeProcess:
    def __init__(self, content, status=0):
        self.stdout = io.BytesIO(content)
        self.status = status
        self.killed = False

    def wait(self, timeout=None):
        return self.status

    def poll(self):
        return self.status

    def kill(self):
        self.killed = True


class BoundedCliTests(unittest.TestCase):
    def test_binary_stream_is_limited_and_no_stderr_or_shell(self):
        process = FakeProcess(b"x" * 200_000)
        with mock.patch.object(fetcher.subprocess, "Popen", return_value=process) as popen:
            with self.assertRaisesRegex(fetcher.FetchError, "github_get_size_limit"):
                fetcher.capture_bounded(["gh.exe", "api"], {}, limit=100_000, timeout=2)
        options = popen.call_args.kwargs
        self.assertFalse(options["shell"])
        self.assertEqual(options["stdin"], fetcher.subprocess.DEVNULL)
        self.assertEqual(options["stderr"], fetcher.subprocess.DEVNULL)

    def test_missing_cli_and_denied_get_have_constant_errors(self):
        with mock.patch.object(fetcher.subprocess, "Popen",
                               side_effect=OSError("credential-like private detail")):
            with self.assertRaisesRegex(fetcher.FetchError, "^existing_local_gh_unavailable$"):
                fetcher.capture_bounded(["gh.exe"], {}, 128, 2)
        with mock.patch.object(fetcher.subprocess, "Popen",
                               return_value=FakeProcess(b"hidden stderr", status=1)):
            with self.assertRaisesRegex(fetcher.FetchError, "^github_get_denied_or_failed$"):
                fetcher.capture_bounded(["gh.exe"], {}, 128, 2)

    def test_success_binary_is_not_decoded(self):
        with mock.patch.object(fetcher.subprocess, "Popen",
                               return_value=FakeProcess(b"\x00\xff\x80")):
            result = fetcher.capture_bounded(["gh.exe"], {}, 128, 2)
        self.assertEqual(result, b"\x00\xff\x80")


if __name__ == "__main__":
    unittest.main()
