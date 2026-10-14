"""Contract tests. Fake Docker transport is not physical host evidence."""
import base64
import copy
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts" / "reqsys_kb_route_binding_probe.py"
SPEC = importlib.util.spec_from_file_location("kb_route_binding", PATH)
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)

TUNNEL, EDGE, API, KB = (c * 64 for c in "1234")
NET = "5" * 64
SHA = "a" * 40
ORIGIN = "https://authorized-dev.trycloudflare.com"
PROJECT = "wt-pc24x7-piloto"


def item(identifier, service, name=None, project=PROJECT, port=None):
    return {
        "id": identifier, "name": "/" + (name or service), "project": project,
        "service": service, "running": True, "image_id": "sha256:" + "f" * 64,
        "config_files": "C:/private-root/docker-compose.yml,C:/private-root/docker-compose.dev.yml",
        "instance": None, "source_sha": SHA,
        "ports": {"80/tcp": [{"HostPort": str(port)}]} if port else {},
        "networks": {"dev-net": {"NetworkID": NET, "Aliases": [service]}},
    }


class Fake:
    def __init__(self, with_kb=True):
        self.items = [item(TUNNEL, "", "reqsys-dev-gateway-tunnel"),
                      item(EDGE, "gateway", port=8083), item(API, "api")]
        if with_kb:
            self.items.append(item(KB, "kb"))
        self.calls = []
        self.change_inventory = False
        self.change_locator = False
        self.inventory_calls = self.locator_calls = 0

    def locator(self):
        self.locator_calls += 1
        self.calls.append("locator")
        origin = "https://different-dev.trycloudflare.com" if (
            self.change_locator and self.locator_calls > 1) else ORIGIN
        return {"origin": origin, "issued_at": 1000, "expires_at": 1900,
                "envelope_sha256": "b" * 64}

    def inventory(self):
        self.inventory_calls += 1
        self.calls.append("inventory")
        values = copy.deepcopy(self.items)
        if self.change_inventory and self.inventory_calls > 1:
            values[1]["image_id"] = "sha256:" + "e" * 64
        return values

    def tunnel(self, identifier):
        self.calls.append("tunnel")
        return "http://host.docker.internal:8083", {ORIGIN}

    def surface(self, gateway_id, kb_id, target):
        self.calls.append("surface")
        body = json.dumps({"info": {"title": "Internal Knowledge Base API"},
                           "paths": {path: {} for path in
                             ("/health", "/projects", "/events",
                              "/validation-runs/ingest")}}).encode()
        direct = probe.openapi_fingerprint(200, body)
        return probe.classify_surface(
            probe.response_fingerprint(200, b"frontend"),
            {**probe.response_fingerprint(200, b"{}"),
             "reqsys_build_identity_matches": True},
            probe.openapi_fingerprint(200, body), direct,
            probe.response_fingerprint(404, b"missing"),
        )


class RouteContracts(unittest.TestCase):
    def test_positive_independent_readback(self):
        fake = Fake()
        result = probe.collect(fake, clock=lambda: 1100)
        self.assertEqual(result["gateway"]["container_id"], EDGE)
        self.assertEqual(result["kb"]["container_id"], KB)
        self.assertTrue(result["independent_metadata_readback"])
        self.assertEqual(fake.inventory_calls, 2)
        self.assertFalse(result["loaded_config_verified"])
        self.assertFalse(result["host_inventory_complete"])

    def test_no_kb_is_scoped_not_machine_absence(self):
        result = probe.collect(Fake(False), clock=lambda: 1100)
        self.assertIsNone(result["kb"])
        self.assertEqual(result["kb_absence_scope"], "selected_compose_project_only")
        self.assertIsNone(result["KB_WRITE_TOKEN_present"])
        self.assertIsNone(result["KB_INGEST_ROOT_present"])

    def test_repeat_is_idempotent(self):
        self.assertEqual(probe.collect(Fake(), clock=lambda: 1100),
                         probe.collect(Fake(), clock=lambda: 1100))

    def test_raw_paths_and_origin_not_exported(self):
        raw = json.dumps(probe.collect(Fake(), clock=lambda: 1100))
        self.assertNotIn("private-root", raw)
        self.assertNotIn(ORIGIN, raw)
        self.assertNotIn("Config.Env", probe.FORMAT)

    def test_inventory_change_blocks(self):
        fake = Fake()
        fake.change_inventory = True
        with self.assertRaisesRegex(probe.Blocked, "metadata_changed"):
            probe.collect(fake, clock=lambda: 1100)

    def test_tunnel_change_blocks(self):
        fake = Fake()
        fake.change_locator = True
        with self.assertRaisesRegex(probe.Blocked, "tunnel_binding_changed"):
            probe.collect(fake, clock=lambda: 1100)

    def test_expiry_before_docker(self):
        fake = Fake()
        with self.assertRaisesRegex(probe.Blocked, "locator_expired"):
            probe.collect(fake, clock=lambda: 1900)
        self.assertEqual(fake.inventory_calls, 0)

    def test_expiry_before_completion(self):
        with self.assertRaisesRegex(probe.Blocked, "locator_expired"):
            probe.collect(Fake(), clock=iter([1100, 1900]).__next__)

    def test_no_origin_match_blocks(self):
        fake = Fake()
        fake.tunnel = lambda _: ("http://host.docker.internal:8083", set())
        with self.assertRaisesRegex(probe.Blocked, "signed_origin_tunnel_not_unique"):
            probe.collect(fake, clock=lambda: 1100)

    def test_two_matching_tunnels_block(self):
        fake = Fake()
        fake.items.append(item("6" * 64, "", "reqsys-dev-failover-tunnel"))
        with self.assertRaisesRegex(probe.Blocked, "signed_origin_tunnel_not_unique"):
            probe.collect(fake, clock=lambda: 1100)

    def test_two_port_bindings_block(self):
        fake = Fake()
        fake.items.append(item("6" * 64, "nginx", port=8083))
        with self.assertRaisesRegex(probe.Blocked, "local_destination_not_unique"):
            probe.collect(fake, clock=lambda: 1100)

    def test_unapproved_project_blocks(self):
        fake = Fake()
        fake.items[1]["project"] = "production"
        with self.assertRaisesRegex(probe.Blocked, "destination_project_unapproved"):
            probe.collect(fake, clock=lambda: 1100)

    def test_disallowed_tunnel_arguments(self):
        for args in (["tunnel", "--url", "http://evil/"],
                     ["tunnel", "--url", "http://caddy:80", "--token", "sentinel"],
                     ["run", "http://caddy:80"]):
            with self.subTest(args=args), self.assertRaises(probe.Blocked):
                probe.route_target(args)

    def test_both_known_tunnel_shapes(self):
        for target in ("http://host.docker.internal:8083", "http://caddy:80"):
            self.assertEqual(probe.route_target(["tunnel", "--url", target]), target)
            self.assertEqual(probe.route_target(["--no-autoupdate", "tunnel", "--url", target]), target)

    def test_portable_network_binding(self):
        values = [item(TUNNEL, "", "reqsys-dev-selfhosted-tunnel-primary"),
                  item(EDGE, "caddy"), item(API, "gateway")]
        result = probe.select_chain(values, TUNNEL, "http://caddy:80")
        self.assertEqual(result["edge_id"], EDGE)
        self.assertEqual(result["gateway_id"], API)

    def test_portable_network_mismatch(self):
        values = [item(TUNNEL, "", "reqsys-dev-selfhosted-tunnel-primary"),
                  item(EDGE, "caddy"), item(API, "gateway")]
        values[1]["networks"]["dev-net"]["NetworkID"] = "9" * 64
        with self.assertRaises(probe.Blocked):
            probe.select_chain(values, TUNNEL, "http://caddy:80")

    def test_bad_metadata_does_not_leak(self):
        value = item(EDGE, "gateway")
        value["config_files"] = "sentinel_secret"
        with self.assertRaisesRegex(probe.Blocked, "^compose_config_name_unapproved$"):
            probe.safe_metadata(value)

    def test_unapproved_origin(self):
        for value in ("http://x.trycloudflare.com", ORIGIN + "/path", ORIGIN + "?x=y",
                      "https://user:secret@x.trycloudflare.com", "https://127.0.0.1"):
            with self.subTest(value=value), self.assertRaises(probe.Blocked):
                probe.checked_origin(value)

    def test_host_fails_before_subprocess(self):
        with patch.object(probe.socket, "gethostname", return_value="WRONG-HOST"):
            with patch.object(probe.subprocess, "run") as command:
                with self.assertRaisesRegex(probe.Blocked, "physical_host_not_authorized"):
                    probe.Live()
                command.assert_not_called()


class SignedLocatorContracts(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        self.key = Ed25519PrivateKey.generate()
        self.public = base64.b64encode(self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.payload = {"environment": "dev", "issued_at": 1000, "expires_at": 1900,
                        "urls": [ORIGIN], "selected_url": ORIGIN,
                        "runtime_contract": {"version": "2.0.0",
                          "static_frontend_required": True, "vite_hmr_forbidden": True,
                          "required_endpoints": ["/api/health", "/api/runtime/health",
                              "/api/runtime/readiness", "/api/runtime/build-info"]}}

    def envelope(self, payload=None, corrupt=False):
        encoded = base64.b64encode(json.dumps(payload or self.payload).encode()).decode()
        signature = self.key.sign(encoded.encode())
        if corrupt:
            signature = b"\x00" * 64
        msg = json.dumps({"v": 1, "payload_b64": encoded,
                         "signature_b64": base64.b64encode(signature).decode()})
        return json.dumps({"event": "message", "title": "reqsys-dev-locator", "message": msg}).encode()

    def test_valid_signature(self):
        with patch.object(probe, "PUBLIC_KEY", self.public):
            self.assertEqual(probe.verify_locator(self.envelope(), 1100)["origin"], ORIGIN)

    def test_tampered_signature(self):
        with patch.object(probe, "PUBLIC_KEY", self.public), self.assertRaises(probe.Blocked):
            probe.verify_locator(self.envelope(corrupt=True), 1100)

    def test_prod_is_not_dev_even_when_signed(self):
        self.payload["environment"] = "prod"
        with patch.object(probe, "PUBLIC_KEY", self.public), self.assertRaises(probe.Blocked):
            probe.verify_locator(self.envelope(), 1100)

    def test_expired_envelope(self):
        with patch.object(probe, "PUBLIC_KEY", self.public), self.assertRaises(probe.Blocked):
            probe.verify_locator(self.envelope(), 1900)

    def test_unknown_signer(self):
        with self.assertRaises(probe.Blocked):
            probe.verify_locator(self.envelope(), 1100)

    def test_missing_runtime_endpoint(self):
        self.payload["runtime_contract"]["required_endpoints"] = []
        with patch.object(probe, "PUBLIC_KEY", self.public), self.assertRaises(probe.Blocked):
            probe.verify_locator(self.envelope(), 1100)

    def test_malformed_rows_ignored(self):
        with patch.object(probe, "PUBLIC_KEY", self.public):
            result = probe.verify_locator(b"not-json\n[]\n" + self.envelope(), 1100)
            self.assertEqual(result["origin"], ORIGIN)


class EvidenceFileContracts(unittest.TestCase):
    def test_main_writes_only_fixed_sanitized_evidence(self):
        sample = {
            "schema_version": "1.0.0", "status": "route_identity_observed_config_pending",
            "host": probe.HOST, "environment": "dev", "runtime_changed": False,
            "locator_signature_verified": True, "independent_metadata_readback": True,
            "loaded_config_verified": False, "host_inventory_complete": False,
            "gateway": {"manifest_names_from_labels": ["docker-compose.yml"]},
            "kb": None,
        }
        sha = "a" * 40
        argv = ["probe", "--correlation-id", "kb-route-binding-test",
                "--expected-collector-sha", sha, "--evidence-file",
                "artifacts/kb-route-binding/evidence.json"]
        old = probe.os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            probe.os.chdir(directory)
            try:
                with patch.object(sys, "argv", argv), patch.object(probe, "Live", return_value=object()), \
                     patch.object(probe, "collect", return_value=sample):
                    self.assertEqual(probe.main(), 0)
                path = Path("artifacts/kb-route-binding/evidence.json")
                written = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(written["expected_collector_sha"], sha)
                self.assertEqual(written["correlation_id"], "kb-route-binding-test")
                raw = path.read_text(encoding="utf-8")
                for forbidden in ("Config.Env", "KB_WRITE_TOKEN=", "private-root", ORIGIN):
                    self.assertNotIn(forbidden, raw)
            finally:
                probe.os.chdir(old)

    def test_main_rejects_any_other_evidence_path_before_collection(self):
        argv = ["probe", "--correlation-id", "kb-route-binding-test",
                "--expected-collector-sha", "a" * 40,
                "--evidence-file", "elsewhere.json"]
        with patch.object(sys, "argv", argv), patch.object(probe, "Live") as live:
            with self.assertRaisesRegex(probe.Blocked, "evidence_path_unapproved"):
                probe.main()
            live.assert_not_called()


class _TransportHandler(BaseHTTPRequestHandler):
    mode = "normal"
    protocol_version = "HTTP/1.0"

    @staticmethod
    def openapi():
        return {
            "openapi": "3.1.0",
            "info": {"title": "Internal Knowledge Base API", "version": "1.0.0"},
            "paths": {
                "/health": {"get": {}},
                "/projects": {"get": {}, "post": {}},
                "/events": {"get": {}, "post": {}},
                "/validation-runs/ingest": {"post": {}},
            },
        }

    def send_bytes(self, status, body, **headers):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        mode = type(self).mode
        if self.path == "/api/runtime/build-info" and mode == "drip_headers":
            try:
                for fragment in (
                        b"HTTP/1.0 200 OK\r\n",
                        b"Content-Type: application/json\r\n",
                        b"Content-Length: 2\r\n", b"\r\n", b"{}"):
                    self.connection.sendall(fragment)
                    time.sleep(0.04)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        elif self.path == "/api/runtime/build-info" and mode == "drip_body":
            self.send_response(200)
            self.send_header("Content-Length", "6")
            self.end_headers()
            try:
                for byte in b"abcdef":
                    self.wfile.write(bytes((byte,)))
                    self.wfile.flush()
                    time.sleep(0.04)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        elif self.path == "/" and mode == "redirect":
            self.send_bytes(302, b"", Location="/api/runtime/build-info")
        elif self.path == "/api/runtime/build-info" and mode == "slow":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"a")
            self.wfile.flush()
            time.sleep(0.4)
            try:
                self.wfile.write(b"b")
            except (BrokenPipeError, ConnectionResetError):
                pass
        elif self.path == "/kb/openapi.json" and mode == "oversized":
            self.send_bytes(200, b"x" * (probe.MAX_BYTES + 1))
        elif self.path == "/openapi.json":
            body = json.dumps(self.openapi(), sort_keys=True).encode()
            status = 503 if mode == "direct_error" else 200
            if mode in {"direct_slow", "direct_drip"}:
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    if mode == "direct_drip":
                        for byte in body:
                            self.wfile.write(bytes((byte,)))
                            self.wfile.flush()
                            time.sleep(0.04)
                    else:
                        self.wfile.write(body[:1])
                        self.wfile.flush()
                        time.sleep(0.4)
                        self.wfile.write(body[1:])
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
            else:
                self.send_bytes(status, body)
        elif self.path == "/api/runtime/build-info":
            self.send_bytes(200, json.dumps({"build_sha": "a" * 40}).encode())
        elif self.path == "/kb/openapi.json":
            self.send_bytes(200, json.dumps(self.openapi(), sort_keys=True).encode())
        elif self.path == "/":
            self.send_bytes(200, b"frontend")
        else:
            self.send_bytes(404, b"missing")

    def log_message(self, *_):
        pass


class LocalSurfaceContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _TransportHandler)
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        _TransportHandler.mode = "normal"

    @staticmethod
    def response(status, body, *, openapi=False, build=False):
        raw = body if isinstance(body, bytes) else json.dumps(body, sort_keys=True).encode()
        if openapi:
            return probe.openapi_fingerprint(status, raw)
        if build:
            return probe.build_info_fingerprint(status, raw)
        return probe.response_fingerprint(status, raw)

    def openapi(self):
        return _TransportHandler.openapi()

    def classify(self, routed, upstream, fallback=b"frontend-missing",
                 frontend_status=200, api_ok=True):
        api = self.response(200, {"build_sha": "a" * 40}, build=True)
        if not api_ok:
            api["reqsys_build_identity_matches"] = False
        return probe.classify_surface(
            self.response(frontend_status, b"frontend"), api,
            routed, upstream, self.response(404, fallback),
        )

    def test_upstream_contract_observed_route_404(self):
        result = self.classify(self.response(404, b"route-missing", openapi=True),
                               self.response(200, self.openapi(), openapi=True))
        self.assertEqual(result["classification"],
                         "upstream_contract_observed_route_404")
        self.assertFalse(result["documents_match"])

    def test_upstream_failure(self):
        result = self.classify(self.response(404, b"missing", openapi=True),
                               self.response(503, b"", openapi=True),
                               fallback=b"missing")
        self.assertEqual(result["classification"],
                         "upstream_contract_not_confirmed")
        self.assertTrue(result["fallback_matches_routed_404"])

    def test_same_contract_requires_gateway_identity_and_equal_documents(self):
        direct = self.response(200, self.openapi(), openapi=True)
        result = self.classify(direct, direct)
        self.assertEqual(result["classification"],
                         "same_contract_through_route_observed")
        self.assertTrue(result["documents_match"])
        degraded = self.classify(direct, direct, api_ok=False)
        self.assertEqual(degraded["classification"],
                         "gateway_identity_not_confirmed")

    def test_different_documents_are_not_associated(self):
        routed_doc = self.openapi()
        routed_doc["info"]["version"] = "1.0.1"
        routed = self.response(200, routed_doc, openapi=True)
        upstream = self.response(200, self.openapi(), openapi=True)
        result = self.classify(routed, upstream)
        self.assertEqual(result["classification"],
                         "route_and_upstream_contracts_differ")
        self.assertFalse(result["documents_match"])

    def test_contract_requires_openapi_versions_methods_and_structures(self):
        good = self.response(200, self.openapi(), openapi=True)
        self.assertTrue(good["openapi_contract_matches"])
        variants = []
        for mutate in ("openapi", "info_version", "method", "path_type"):
            value = self.openapi()
            if mutate == "openapi":
                value.pop("openapi")
            elif mutate == "info_version":
                value["info"].pop("version")
            elif mutate == "method":
                value["paths"]["/projects"].pop("post")
            else:
                value["paths"]["/events"] = []
            variants.append(value)
        for value in variants:
            with self.subTest(value=value):
                self.assertFalse(self.response(200, value, openapi=True)
                                 ["openapi_contract_matches"])

    def test_non_object_json_is_fail_closed(self):
        for value in ([], None, 7, "not-an-object"):
            with self.subTest(value=value):
                result = self.response(200, value, openapi=True)
                self.assertFalse(result["openapi_contract_matches"])

    def test_non_200_openapi_body_does_not_confirm_upstream(self):
        upstream = self.response(503, self.openapi(), openapi=True)
        self.assertFalse(upstream["openapi_contract_matches"])
        result = self.classify(self.response(404, b"missing", openapi=True), upstream)
        self.assertEqual(result["classification"],
                         "upstream_contract_not_confirmed")

    def test_proxy_environment_is_ignored_and_redirect_is_not_followed(self):
        _TransportHandler.mode = "redirect"
        env = {"HTTP_PROXY": "http://127.0.0.1:1",
               "HTTPS_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""}
        with patch.dict(os.environ, env, clear=False):
            status, body = probe.bounded_http_get(
                "127.0.0.1", self.port, "/", deadline_seconds=1)
        self.assertEqual(status, 302)
        self.assertEqual(body, b"")

    def assert_gateway_deadline(self, mode):
        _TransportHandler.mode = mode
        started = time.monotonic()
        with self.assertRaisesRegex(probe.Blocked, "gateway_http_deadline"):
            probe.bounded_http_get("127.0.0.1", self.port,
                                   "/api/runtime/build-info",
                                   deadline_seconds=0.1)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_gateway_total_deadline_stops_inactive_body(self):
        self.assert_gateway_deadline("slow")

    def test_gateway_total_deadline_stops_drip_headers(self):
        self.assert_gateway_deadline("drip_headers")

    def test_gateway_total_deadline_stops_drip_body(self):
        self.assert_gateway_deadline("drip_body")

    def test_gateway_oversized_body_is_blocked(self):
        _TransportHandler.mode = "oversized"
        with self.assertRaisesRegex(probe.Blocked, "gateway_http_body_too_large"):
            probe.bounded_http_get("127.0.0.1", self.port,
                                   "/kb/openapi.json", deadline_seconds=1)

    def direct_script(self, deadline="1.0"):
        return (probe.DIRECT_OPENAPI_SCRIPT
                .replace('"127.0.0.1", 8080',
                         f'"127.0.0.1", {self.port}')
                .replace("DEADLINE_SECONDS = 5.0",
                         f"DEADLINE_SECONDS = {deadline}"))

    def test_internal_script_real_get_exports_only_closed_summary(self):
        result = subprocess.run([sys.executable, "-c", self.direct_script()],
                                capture_output=True, text=True, timeout=3,
                                check=True)
        value = json.loads(result.stdout)
        self.assertEqual(probe.validate_direct_summary(value), value)
        self.assertTrue(value["openapi_contract_matches"])
        self.assertNotIn("body", value)

    def test_internal_script_non_200_and_total_deadline(self):
        _TransportHandler.mode = "direct_error"
        result = subprocess.run([sys.executable, "-c", self.direct_script()],
                                capture_output=True, text=True, timeout=3,
                                check=True)
        self.assertFalse(json.loads(result.stdout)["openapi_contract_matches"])
        for mode in ("direct_slow", "direct_drip"):
            with self.subTest(mode=mode):
                _TransportHandler.mode = mode
                started = time.monotonic()
                result = subprocess.run(
                    [sys.executable, "-c", self.direct_script("0.1")],
                    capture_output=True, text=True, timeout=2, check=True)
                summary = json.loads(result.stdout)
                self.assertEqual(summary["http_status"], 599)
                self.assertEqual(summary["body_bytes"], 0)
                self.assertFalse(summary["openapi_contract_matches"])
                self.assertLess(time.monotonic() - started, 1.0)

    def test_summary_rejects_extra_or_malformed_fields(self):
        good = {"http_status": 200, "body_bytes": 10, "body_sha256": "a" * 64,
                "openapi_contract_matches": True}
        self.assertEqual(probe.validate_direct_summary(good), good)
        for bad in ({**good, "body": "secret"},
                    {**good, "body_sha256": "bad"},
                    {**good, "openapi_contract_matches": 1}):
            with self.subTest(bad=bad), self.assertRaises(probe.Blocked):
                probe.validate_direct_summary(bad)

    def test_internal_get_is_fixed_and_does_not_initialize_app(self):
        script = probe.DIRECT_OPENAPI_SCRIPT
        self.assertIn('HTTPConnection("127.0.0.1", 8080', script)
        self.assertIn('connection.request("GET", "/openapi.json"', script)
        self.assertNotIn("uvicorn", script)
        self.assertNotIn("main:app", script)
        self.assertNotIn("Config.Env", script)
        self.assertNotIn('request("GET", "/health"', script)


class PhysicalWorkflowContracts(unittest.TestCase):
    def setUp(self):
        self.workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" /
                         "kb-route-binding-physical-readonly.yml").read_text(encoding="utf-8")

    def test_source_is_workspace_root_and_rules_are_untracked_nested_checkout(self):
        self.assertIn("path: _rules", self.workflow)
        self.assertNotIn("path: source", self.workflow)
        self.assertNotIn("path: rules", self.workflow)
        self.assertIn("'--policy', $policy, '--repo', $env:GITHUB_WORKSPACE,", self.workflow)
        self.assertIn("$rules = Join-Path $env:GITHUB_WORKSPACE '_rules'", self.workflow)

    def test_execution_stays_in_launcher_target_and_trigger_is_one_shot(self):
        self.assertIn("'run', '--cwd', $env:TARGET_PATH, '--session-id', $env:SESSION_ID,", self.workflow)
        self.assertIn("path: ${{ steps.session.outputs.target_path }}/artifacts/kb-route-binding/evidence.json", self.workflow)
        self.assertEqual(self.workflow.count(".github/kb-route-binding-authorized-once-20261013"), 1)
        self.assertNotIn("workflow_dispatch:", self.workflow)


if __name__ == "__main__":
    unittest.main()
