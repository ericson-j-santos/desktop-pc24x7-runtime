"""Read-only source selection must not expose credentials or alter the gateway."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "reqsys_dev_current_data_probe.py"
spec = importlib.util.spec_from_file_location("current_data_probe", PATH)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

GATEWAY = "a" * 64
API = "b" * 64
DATABASE = "c" * 64
PROJECT = "wt-pc24x7-piloto"


def container(identifier, service, env=(), ports=None):
    return {"Id": identifier, "Config": {
        "WorkingDir": "/app", "Env": list(env),
        "Labels": {"com.docker.compose.project": PROJECT,
                   "com.docker.compose.service": service}},
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "NetworkSettings": {"Ports": ports or {}, "Networks": {
            "owned": {"NetworkID": "d" * 64, "Aliases": [service]}}},
        "Mounts": [{"Type": "volume", "Destination": "/var/lib/postgresql/data",
                    "Source": "/irrelevant/private", "RW": True}]}


def test_database_classification_does_not_return_password_or_url():
    item = container(API, "api", ["DATABASE_URL=postgresql+psycopg2://reqsys_app:placeholder-sensitive-value@db:5432/reqsys"])
    result = probe.configured_database(item)
    assert result == {"dialect": "postgresql", "database": "reqsys", "role": "reqsys_app",
                      "configuration_source": "container_environment"}
    assert "placeholder-sensitive-value" not in json.dumps(result)
    assert "postgresql+" not in json.dumps(result)


@pytest.mark.parametrize("raw", [
    "postgresql://reqsys_app:placeholder@outside-host:5432/reqsys",
    "postgresql://reqsys_app:placeholder@db:9000/reqsys",
    "sqlite:////private/credential.db",
    "mysql://reqsys_app:placeholder@db:3306/reqsys",
])
def test_other_database_targets_are_blocked(raw):
    with pytest.raises(probe.ProbeFailure):
        probe.configured_database(container(API, "api", ["DATABASE_URL=" + raw]))


def test_missing_env_database_is_unresolved_and_never_assumed_sqlite():
    assert probe.configured_database(container(API, "api"))["dialect"] == "unresolved"


def test_non_dev_projects_and_environments_are_blocked():
    item = container(API, "api")
    with pytest.raises(probe.ProbeFailure, match="unapproved_dev_project"):
        probe.validate_dev(item, "reqsys-prod", "api")
    item["Config"]["Env"] = ["APP_ENV=production"]
    with pytest.raises(probe.ProbeFailure, match="non_dev_environment_blocked"):
        probe.validate_dev(item, PROJECT, "api")


def test_postgres_reader_uses_only_fixed_readonly_sql_and_no_password(monkeypatch):
    item = container(DATABASE, "db", ["POSTGRES_USER=reqsys_app", "POSTGRES_DB=reqsys",
                                     "POSTGRES_PASSWORD=placeholder-sensitive-value"])
    payload = {"database": "reqsys", "role": "reqsys_app", "table_counts": {"items": 9},
               "table_limit_exceeded": False, "modification_stats": {}}
    commands = []
    def run(command, timeout=20):
        commands.append(command)
        assert command[:3] == ["docker", "exec", DATABASE]
        assert "--no-password" in command
        assert "placeholder-sensitive-value" not in " ".join(command)
        assert "READ ONLY" in command[-1]
        assert "statement_timeout" in command[-1]
        assert "INSERT " not in command[-1] and "DELETE " not in command[-1] and "UPDATE " not in command[-1]
        return "BEGIN\n" + json.dumps(payload) + "\nCOMMIT\n"
    monkeypatch.setattr(probe, "run", run)
    result = probe.postgres_metadata("docker", item, {"database": "reqsys"})
    assert result["counts_exact"] is True
    assert result["data_freshness_proven"] is False
    assert len(commands) == 1


def test_gateway_source_selection_reports_owned_postgres_and_keeps_secrets_private(monkeypatch):
    gateway = container(GATEWAY, "nginx", ports={"80/tcp": [{"HostPort": "8083"}]})
    api = container(API, "api", [
        "DATABASE_URL=postgresql+psycopg2://reqsys_app:placeholder-db-secret@db:5432/reqsys",
        "JWT_SECRET=placeholder-jwt-secret",
    ])
    database = container(DATABASE, "db", [
        "POSTGRES_USER=reqsys_app", "POSTGRES_DB=reqsys",
        "POSTGRES_PASSWORD=placeholder-postgres-secret",
    ])
    inventory = [
        {"id": GATEWAY, "name": "owned-nginx", "project": PROJECT, "service": "nginx",
         "published_ports": "0.0.0.0:8083->80/tcp", "state": "running", "status": "healthy"},
        {"id": API, "name": "owned-api", "project": PROJECT, "service": "api",
         "published_ports": "0.0.0.0:8210->8000/tcp", "state": "running", "status": "healthy"},
        {"id": DATABASE, "name": "owned-db", "project": PROJECT, "service": "db",
         "published_ports": "", "state": "running", "status": "healthy"},
    ]
    monkeypatch.setattr(probe, "require_host", lambda: None)
    monkeypatch.setattr(probe.shutil, "which", lambda _: "docker")
    monkeypatch.setattr(probe, "run", lambda *args, **kwargs: "\n".join(map(json.dumps, inventory)))
    monkeypatch.setattr(probe, "inspected", lambda _, identifier: {GATEWAY: gateway, API: api, DATABASE: database}[identifier])
    monkeypatch.setattr(probe, "build_info", lambda: {"http_status": 200, "build_sha": "f" * 40})
    monkeypatch.setattr(probe, "nginx_api_route", lambda *args: {"verified": True})
    monkeypatch.setattr(probe, "postgres_metadata", lambda *args: {"table_counts": {"items": 12}, "counts_exact": True})
    result = probe.collect()
    serialized = json.dumps(result)
    assert result["status"] == "observed"
    assert result["project"] == PROJECT
    assert result["sqlite_backup_is_current_source"] is False
    assert result["cutover_ready"] is False
    assert result["services_changed"] is False
    assert "placeholder-db-secret" not in serialized
    assert "placeholder-jwt-secret" not in serialized
    assert "placeholder-postgres-secret" not in serialized
    assert "/irrelevant/private" not in serialized


def test_gateway_port_binding_and_network_identity_must_match():
    api = container(API, "api")
    database = container(DATABASE, "db")
    assert probe.shared_db_network(api, database)
    database["NetworkSettings"]["Networks"]["owned"]["NetworkID"] = "e" * 64
    assert not probe.shared_db_network(api, database)
    gateway = container(GATEWAY, "nginx", ports={"80/tcp": [{"HostPort": "8084"}]})
    assert probe.host_port(gateway, 8083) is False



def test_nginx_route_proves_owned_api_without_exporting_config_credentials(monkeypatch):
    gateway = container(GATEWAY, "nginx")
    gateway["Config"]["Image"] = "nginx:alpine"
    api = container(API, "api")
    configuration = """
    server {
      location /api/ {
        proxy_set_header X-Private placeholder-config-secret;
        proxy_pass http://api:8000/api/;
      }
    }
    """
    monkeypatch.setattr(probe, "run", lambda *args, **kwargs: configuration)
    result = probe.nginx_api_route("docker", gateway, api)
    assert result["verified"] is True
    assert "placeholder-config-secret" not in json.dumps(result)
    monkeypatch.setattr(probe, "run", lambda *args, **kwargs: "server { location /api/ { proxy_pass http://another-api:8000/; } }")
    assert probe.nginx_api_route("docker", gateway, api)["verified"] is False


def test_nginx_named_upstream_is_restricted_to_owned_api(monkeypatch):
    gateway = container(GATEWAY, "nginx")
    gateway["Config"]["Image"] = "nginx:alpine"
    api = container(API, "api")
    monkeypatch.setattr(probe, "run", lambda *args, **kwargs:
        "upstream reqsys_api { server api:8000; } server { location /api/ { proxy_pass http://reqsys_api/api/; } }")
    assert probe.nginx_api_route("docker", gateway, api)["verified"] is True
