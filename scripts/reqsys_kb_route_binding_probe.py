"""Fixed Desktop DEV route inventory; no changes to runtime or credentials.

Run only inside an independently validated Command Gateway session.
The collector does not activate services, execute commands inside containers,
read databases, resolve arbitrary URLs, or treat a source SHA as host identity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

HOST = "DESKTOP-PDQK954"
PROJECTS = frozenset(("wt-pc24x7-piloto", "wt-pc24x7-piloto-governado",
                      "reqsys-dev", "reqsys-dev-selfhosted"))
TUNNELS = frozenset(("reqsys-dev-gateway-tunnel", "reqsys-dev-failover-tunnel",
                     "reqsys-dev-selfhosted-tunnel-primary",
                     "reqsys-dev-selfhosted-tunnel-secondary"))
LOCATOR = "https://ntfy.sh/reqsys-dev-locator-1651e9182d6e1c939fa6672c1248c9d532716fe7/json?poll=1&since=1h"
PUBLIC_KEY = "Ox1kIxgrkNTG96NI69Obi/W+ZiZz2jxw3DLCQMvwMcM="
URL_RE = re.compile(r"https://[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com")
ID_RE = re.compile(r"[0-9a-f]{64}")
SHA_RE = re.compile(r"[0-9a-f]{40}")
MAX_BYTES = 1048576
GATEWAY_ORIGIN = "http://127.0.0.1:8083"
GATEWAY_PATHS = frozenset(("/", "/api/runtime/build-info", "/kb/openapi.json",
                           "/__kb_route_probe_missing__"))
DIRECT_OPENAPI_SCRIPT = (
    "import hashlib,http.client,json;"
    "c=http.client.HTTPConnection('127.0.0.1',8080,timeout=5);"
    "c.request('GET','/openapi.json',headers={'Accept':'application/json',"
    "'User-Agent':'KB-Route-Readonly/1'});r=c.getresponse();b=r.read(1048577);"
    "assert len(b)<=1048576;"
    "\ntry:o=json.loads(b)"
    "\nexcept (ValueError,UnicodeError):o={}"
    "\np=o.get('paths',{}) if isinstance(o,dict) else {};"
    "i=o.get('info',{}) if isinstance(o,dict) else {};"
    "ok=r.status==200 and isinstance(i,dict) and i.get('title')=='Internal Knowledge Base API' "
    "and isinstance(p,dict) and all(x in p for x in "
    "('/health','/projects','/events','/validation-runs/ingest'));"
    "print(json.dumps({'http_status':r.status,'body_bytes':len(b),"
    "'body_sha256':hashlib.sha256(b).hexdigest(),"
    "'openapi_identity_matches':ok},sort_keys=True,separators=(',',':')))"
)
# Deliberately omit Config.Env, command lines, raw labels, and mount source paths.
FORMAT = (
    '{"id":{{json .Id}},"name":{{json .Name}},"image_id":{{json .Image}},'
    '"running":{{json .State.Running}},'
    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"config_files":{{json (index .Config.Labels "com.docker.compose.project.config_files")}},'
    '"instance":{{json (index .Config.Labels "io.reqsys.selfhost.instance")}},'
    '"source_sha":{{json (index .Config.Labels "io.reqsys.selfhost.source_sha")}},'
    '"ports":{{json .NetworkSettings.Ports}},'
    '"networks":{{json .NetworkSettings.Networks}}}'
)


class Blocked(ValueError):
    """Fixed error codes only; never return raw subprocess/HTTP output."""


def need(condition, code):
    if not condition:
        raise Blocked(code)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def checked_origin(value):
    need(isinstance(value, str) and URL_RE.fullmatch(value) is not None,
         "origin_not_allowed")
    return value


def verify_locator(raw, now):
    import base64
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    need(isinstance(raw, bytes) and len(raw) <= MAX_BYTES, "locator_size_invalid")
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY, validate=True))
    candidates = []
    for line in raw.splitlines():
        try:
            row = json.loads(line)
            if row.get("event") != "message" or row.get("title") != "reqsys-dev-locator":
                continue
            envelope = json.loads(row["message"])
            if type(envelope.get("v")) is not int or envelope["v"] != 1:
                continue
            encoded = envelope["payload_b64"]
            key.verify(base64.b64decode(envelope["signature_b64"], validate=True),
                       encoded.encode("ascii"))
            payload = json.loads(base64.b64decode(encoded, validate=True))
            issued, expires = payload["issued_at"], payload["expires_at"]
            contract = payload["runtime_contract"]
            need(payload["environment"] == "dev", "locator_environment_invalid")
            need(type(issued) is int and type(expires) is int
                 and issued <= now + 60 and expires > now
                 and 0 < expires - issued <= 900, "locator_time_invalid")
            need(contract["version"] == "2.0.0"
                 and contract["static_frontend_required"] is True
                 and contract["vite_hmr_forbidden"] is True, "locator_contract_invalid")
            need({"/api/health", "/api/runtime/health", "/api/runtime/readiness",
                  "/api/runtime/build-info"} <= set(contract["required_endpoints"]),
                 "locator_endpoints_invalid")
            urls = payload["urls"]
            need(isinstance(urls, list) and 0 < len(urls) <= 16, "locator_urls_invalid")
            for url in urls:
                checked_origin(url)
            selected = checked_origin(payload["selected_url"])
            need(selected in urls, "locator_selection_invalid")
            candidates.append({"origin": selected, "issued_at": issued,
                               "expires_at": expires,
                               "envelope_sha256": digest(row["message"])})
        except (KeyError, TypeError, ValueError, AttributeError, UnicodeError,
                InvalidSignature):
            continue
    need(bool(candidates), "no_valid_fresh_signed_locator")
    return max(candidates, key=lambda x: x["issued_at"])


def bindings(item, port):
    return any(str(b.get("HostPort")) == str(port)
               for values in (item.get("ports") or {}).values()
               for b in values or [])


def aliases(item, name):
    return {v.get("NetworkID") for v in (item.get("networks") or {}).values()
            if name in (v.get("Aliases") or []) and ID_RE.fullmatch(str(v.get("NetworkID", "")))}


def route_target(tunnel_argv):
    # Only exact argv patterns from the two existing tunnel controllers.
    args = list(tunnel_argv)
    if args[:1] == ["--no-autoupdate"]:
        args = args[1:]
    need(len(args) == 3 and args[:2] == ["tunnel", "--url"], "tunnel_argv_unapproved")
    need(args[2] in {"http://host.docker.internal:8083", "http://caddy:80"},
         "tunnel_target_unapproved")
    return args[2]


def select_chain(items, tunnel_id, target):
    by_id = {x["id"]: x for x in items}
    need(len(by_id) == len(items) and len(items) <= 100, "inventory_not_unique")
    need(all(ID_RE.fullmatch(x["id"]) for x in items), "container_id_invalid")
    tunnel = by_id[tunnel_id]
    need(tunnel["name"].lstrip("/") in TUNNELS and tunnel["running"] is True,
         "tunnel_identity_invalid")
    if target == "http://host.docker.internal:8083":
        candidates = [x for x in items if x.get("running") is True and bindings(x, 8083)]
    elif target == "http://caddy:80":
        tunnel_networks = {v.get("NetworkID") for v in (tunnel.get("networks") or {}).values()}
        candidates = [x for x in items if x.get("running") is True
                      and aliases(x, "caddy") & tunnel_networks]
    else:
        raise Blocked("tunnel_target_unapproved")
    need(len(candidates) == 1, "local_destination_not_unique")
    edge = candidates[0]
    project = edge.get("project")
    need(project in PROJECTS, "destination_project_unapproved")
    if target == "http://host.docker.internal:8083":
        need(edge.get("service") in {"gateway", "nginx"}, "gateway_service_unapproved")
        gateway = edge
    else:
        need(edge.get("service") == "caddy", "caddy_service_unapproved")
        net = {v.get("NetworkID") for v in (edge.get("networks") or {}).values()}
        found = [x for x in items if x.get("project") == project
                 and x.get("service") == "gateway" and x.get("running") is True
                 and aliases(x, "gateway") & net]
        need(len(found) == 1, "gateway_not_unique")
        gateway = found[0]
    kb = [x for x in items if x.get("project") == project and x.get("service") == "kb"]
    need(len(kb) <= 1, "kb_container_not_unique")
    return {"project": project, "edge_id": edge["id"], "gateway_id": gateway["id"],
            "kb_id": kb[0]["id"] if kb else None}


def safe_metadata(item):
    files = item.get("config_files")
    need(isinstance(files, str) and 0 < len(files) <= 8192, "compose_config_labels_missing")
    # Labels identify creation-time manifests, not current loaded config contents.
    names = []
    for value in files.split(","):
        name = value.strip().replace("\\", "/").rsplit("/", 1)[-1]
        need(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.ya?ml", name) is not None,
             "compose_config_name_unapproved")
        names.append(name)
    sha = item.get("source_sha")
    image = item.get("image_id")
    need(isinstance(image, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image),
         "image_id_invalid")
    instance = item.get("instance")
    return {"container_id": item["id"], "service": item.get("service"),
            "project": item.get("project"), "running": item.get("running") is True,
            "image_id": image, "manifest_names_from_labels": names,
            "manifest_paths_sha256": digest(files), "loaded_config_verified": False,
            "source_sha_label": sha if isinstance(sha, str) and SHA_RE.fullmatch(sha) else None,
            "instance_label": instance if instance == "pc24x7-selfhost-dev-v1" else None}


def response_fingerprint(status, raw):
    need(type(status) is int and 100 <= status <= 599, "http_status_invalid")
    need(isinstance(raw, bytes) and len(raw) <= MAX_BYTES, "http_body_invalid")
    return {"http_status": status, "body_bytes": len(raw),
            "body_sha256": hashlib.sha256(raw).hexdigest()}


def openapi_fingerprint(status, raw):
    result = response_fingerprint(status, raw)
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeError):
        obj = {}
    info = obj.get("info", {}) if isinstance(obj, dict) else {}
    paths = obj.get("paths", {}) if isinstance(obj, dict) else {}
    result["openapi_identity_matches"] = (
        status == 200 and isinstance(info, dict)
        and info.get("title") == "Internal Knowledge Base API"
        and isinstance(paths, dict)
        and all(path in paths for path in
                ("/health", "/projects", "/events", "/validation-runs/ingest"))
    )
    return result


def build_info_fingerprint(status, raw):
    result = response_fingerprint(status, raw)
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeError):
        obj = {}
    data = obj.get("data", obj) if isinstance(obj, dict) else {}
    value = data.get("build_sha") or data.get("commit_sha") if isinstance(data, dict) else None
    result["reqsys_build_identity_matches"] = (
        status == 200 and isinstance(value, str) and SHA_RE.fullmatch(value) is not None
    )
    return result


def classify_surface(frontend, api, routed, upstream, fallback):
    direct_ok = upstream.get("openapi_identity_matches") is True
    routed_ok = routed.get("openapi_identity_matches") is True
    if direct_ok and routed_ok:
        classification = "route_and_upstream_valid"
    elif direct_ok and routed.get("http_status") == 404:
        classification = "upstream_valid_route_404"
    elif not direct_ok:
        classification = "upstream_not_confirmed"
    else:
        classification = "route_not_confirmed"
    fallback_match = (
        routed.get("http_status") == fallback.get("http_status") == 404
        and routed.get("body_sha256") == fallback.get("body_sha256")
        and routed.get("body_bytes") == fallback.get("body_bytes")
    )
    return {
        "frontend_gateway_http_status": frontend.get("http_status"),
        "api_gateway_identity_matches": api.get("reqsys_build_identity_matches") is True,
        "routed_kb": routed, "direct_kb": upstream,
        "fallback_control": fallback,
        "fallback_matches_routed_404": fallback_match,
        "classification": classification,
        "raw_bodies_exported": False, "freeform_headers_exported": False,
    }


def validate_direct_summary(value):
    need(isinstance(value, dict)
         and set(value) == {"http_status", "body_bytes", "body_sha256",
                            "openapi_identity_matches"},
         "direct_summary_invalid")
    need(type(value["http_status"]) is int and 100 <= value["http_status"] <= 599,
         "direct_status_invalid")
    need(type(value["body_bytes"]) is int and 0 <= value["body_bytes"] <= MAX_BYTES,
         "direct_size_invalid")
    need(isinstance(value["body_sha256"], str)
         and ID_RE.fullmatch(value["body_sha256"]) is not None,
         "direct_digest_invalid")
    need(type(value["openapi_identity_matches"]) is bool,
         "direct_identity_invalid")
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Live:
    def __init__(self):
        need(os.name == "nt" and socket.gethostname().casefold() == HOST.casefold(),
             "physical_host_not_authorized")
        self.docker = shutil.which("docker")
        need(bool(self.docker), "docker_unavailable")
        self.deadline = time.monotonic() + 90

    def run(self, args):
        remaining = min(10, self.deadline - time.monotonic())
        need(remaining > 0, "collection_deadline")
        try:
            value = subprocess.run([self.docker, *args], stdin=subprocess.DEVNULL,
                                   capture_output=True, timeout=remaining,
                                   check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Blocked("docker_read_unavailable") from None
        need(value.returncode == 0, "docker_read_failed")
        need(len(value.stdout) + len(value.stderr) <= MAX_BYTES, "docker_output_too_large")
        # Tunnel startup URLs may be printed to stderr.
        return value.stdout.decode("utf-8", "strict"), value.stderr.decode("utf-8", "strict")

    def locator(self):
        try:
            request = Request(LOCATOR, headers={"Accept": "application/x-ndjson",
                                              "Cache-Control": "no-store"}, method="GET")
            with build_opener(NoRedirect()).open(request, timeout=10) as response:
                need(response.status == 200, "locator_http_failed")
                raw = response.read(MAX_BYTES + 1)
            return verify_locator(raw, int(time.time()))
        except (URLError, HTTPError, OSError):
            raise Blocked("locator_read_failed") from None

    def inventory(self):
        raw, _ = self.run(["ps", "-a", "--no-trunc", "--format", "{{.ID}}"])
        ids = raw.splitlines()
        need(0 < len(ids) <= 100 and all(ID_RE.fullmatch(x) for x in ids),
             "container_inventory_invalid")
        # One bounded inspect call, exporting selected metadata only.
        raw, _ = self.run(["inspect", "--type", "container", "--format", FORMAT, *ids])
        items = [json.loads(line) for line in raw.splitlines() if line.strip()]
        need({x["id"] for x in items} == set(ids), "inventory_changed_during_read")
        return items


    def gateway_get(self, path):
        need(path in GATEWAY_PATHS, "gateway_path_unapproved")
        request = Request(GATEWAY_ORIGIN + path, method="GET", headers={
            "Accept": "application/json,text/html",
            "Cache-Control": "no-store",
            "User-Agent": "KB-Route-Readonly/1",
        })
        try:
            with build_opener(NoRedirect()).open(request, timeout=5) as response:
                raw = response.read(MAX_BYTES + 1)
                status = response.status
        except HTTPError as exc:
            status = exc.code
            raw = exc.read(MAX_BYTES + 1)
            exc.close()
        except (URLError, OSError, TimeoutError):
            raise Blocked("gateway_http_unavailable") from None
        need(len(raw) <= MAX_BYTES, "gateway_http_body_too_large")
        return status, raw

    def kb_openapi(self, identifier):
        need(ID_RE.fullmatch(identifier) is not None, "container_id_invalid")
        raw, _ = self.run(["exec", identifier, "python", "-c", DIRECT_OPENAPI_SCRIPT])
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Blocked("direct_summary_invalid") from None
        return validate_direct_summary(value)

    def surface(self, gateway_id, kb_id, target):
        need(ID_RE.fullmatch(gateway_id) is not None, "container_id_invalid")
        need(target == "http://host.docker.internal:8083",
             "surface_target_unsupported")
        need(kb_id is not None and ID_RE.fullmatch(kb_id) is not None,
             "kb_container_required_for_surface")
        front_status, front_raw = self.gateway_get("/")
        api_status, api_raw = self.gateway_get("/api/runtime/build-info")
        route_status, route_raw = self.gateway_get("/kb/openapi.json")
        fallback_status, fallback_raw = self.gateway_get("/__kb_route_probe_missing__")
        return classify_surface(
            response_fingerprint(front_status, front_raw),
            build_info_fingerprint(api_status, api_raw),
            openapi_fingerprint(route_status, route_raw),
            self.kb_openapi(kb_id),
            response_fingerprint(fallback_status, fallback_raw),
        )

    def tunnel(self, identifier):
        need(ID_RE.fullmatch(identifier) is not None, "container_id_invalid")
        raw, _ = self.run(["inspect", "--type", "container", "--format", "{{json .Args}}", identifier])
        target = route_target(json.loads(raw))
        out, err = self.run(["logs", "--tail", "120", identifier])
        return target, set(URL_RE.findall(out + "\n" + err))


def collect(transport, clock=time.time):
    locator = transport.locator()
    need(locator["expires_at"] > int(clock()), "locator_expired")
    items = transport.inventory()
    matches = []
    for item in items:
        if item["name"].lstrip("/") not in TUNNELS or item.get("running") is not True:
            continue
        target, origins = transport.tunnel(item["id"])
        if locator["origin"] in origins:
            matches.append((item, target))
    need(len(matches) == 1, "signed_origin_tunnel_not_unique")
    tunnel, target = matches[0]
    chain = select_chain(items, tunnel["id"], target)
    # Probe only after the chain is selected; the independent readback below
    # rejects any switch/recreation that occurs during the fixed GETs.
    surface = transport.surface(chain["gateway_id"], chain["kb_id"], target)
    after = transport.inventory()
    by_id = {x["id"]: x for x in after}
    ids = {tunnel["id"], chain["edge_id"], chain["gateway_id"]}
    if chain["kb_id"]:
        ids.add(chain["kb_id"])
    need(all(x in by_id for x in ids), "container_recreated_during_collection")
    before_by_id = {x["id"]: x for x in items}
    need(all(before_by_id[x] == by_id[x] for x in ids), "metadata_changed_during_collection")
    target_after, origins_after = transport.tunnel(tunnel["id"])
    locator_after = transport.locator()
    need(target_after == target and locator["origin"] in origins_after
         and locator_after["origin"] == locator["origin"], "tunnel_binding_changed")
    need(locator["expires_at"] > int(clock()) and locator_after["expires_at"] > int(clock()),
         "locator_expired")
    return {
        "schema_version": "1.0.0", "status": "route_identity_observed_config_pending",
        "host": HOST, "environment": "dev", "runtime_changed": False,
        "origin_sha256": digest(locator["origin"]), "locator_signature_verified": True,
        "envelope_sha256": locator["envelope_sha256"],
        "tunnel_container_id": tunnel["id"], "local_target": target, **chain,
        "gateway": safe_metadata(by_id[chain["gateway_id"]]),
        "kb": safe_metadata(by_id[chain["kb_id"]]) if chain["kb_id"] else None,
        "independent_metadata_readback": True,
        "kb_absence_scope": "selected_compose_project_only" if not chain["kb_id"] else None,
        "loaded_config_verified": False, "KB_WRITE_TOKEN_present": None,
        "KB_INGEST_ROOT_present": None, "host_inventory_complete": False,
        "surface": surface,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--expected-collector-sha", required=True)
    parser.add_argument("--evidence-file", required=True)
    args = parser.parse_args()
    need(re.fullmatch(r"[A-Za-z0-9_.-]{8,128}", args.correlation_id), "correlation_id_invalid")
    need(SHA_RE.fullmatch(args.expected_collector_sha), "collector_sha_invalid")
    need(args.evidence_file == "artifacts/kb-route-binding/evidence.json",
         "evidence_path_unapproved")
    # Caller must verify SHA/session through Command Gateway before invocation.
    try:
        evidence = collect(Live())
    except Exception as exc:
        evidence = {"status": "blocked", "reason": str(exc) if isinstance(exc, Blocked)
                    else "collection_failed", "runtime_changed": False,
                    "host_inventory_complete": False}
    evidence.update(correlation_id=args.correlation_id,
                    expected_collector_sha=args.expected_collector_sha,
                    observed_at=datetime.now(timezone.utc).isoformat())
    serialized = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    output = Path(args.evidence_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialized, encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["status"] == "route_identity_observed_config_pending" else 2


if __name__ == "__main__":
    raise SystemExit(main())
