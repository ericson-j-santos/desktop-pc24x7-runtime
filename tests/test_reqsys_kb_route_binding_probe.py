"""Contract tests. Fake Docker transport is not physical host evidence."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
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


if __name__ == "__main__":
    unittest.main()
