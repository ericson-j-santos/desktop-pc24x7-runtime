"""Real Docker CLI contract, only in a disposable GitHub-hosted test runner."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("binding", ROOT / "scripts/reqsys_kb_route_binding_probe.py")
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)


def command(args, success=True):
    value = subprocess.run(["docker", *args], capture_output=True, text=True,
                           timeout=90, check=False, shell=False)
    if success and value.returncode:
        raise RuntimeError("disposable_docker_contract_command_failed")
    return value


def main():
    run = os.environ.get("GITHUB_RUN_ID", "")
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or not re.fullmatch(r"[1-9][0-9]*", run)):
        raise SystemExit("disposable_github_hosted_runner_required")
    name = "kb-binding-contract-" + run
    identifier = None
    try:
        identifier = command([
            "create", "--name", name, "--network", "none",
            "--label", "io.reqsys.fixture=kb-route-binding",
            "--label", "com.docker.compose.project=reqsys-dev",
            "--label", "com.docker.compose.service=gateway",
            "--label", "com.docker.compose.project.config_files=C:/fixture/docker-compose.yml",
            "--env", "KB_WRITE_TOKEN=DISPOSABLE-NONSECRET-SENTINEL",
            "alpine:3.20", "true",
        ]).stdout.strip()
        if not binding.ID_RE.fullmatch(identifier):
            raise RuntimeError("fixture_id_invalid")
        observed = command(["inspect", "--type", "container", "--format",
                            binding.FORMAT, identifier]).stdout
        value = json.loads(observed)
        assert value["id"] == identifier and value["running"] is False
        assert value["project"] == "reqsys-dev" and value["service"] == "gateway"
        assert "DISPOSABLE-NONSECRET-SENTINEL" not in observed
        assert "KB_WRITE_TOKEN" not in observed
        safe = binding.safe_metadata(value)
        assert safe["loaded_config_verified"] is False
        assert safe["manifest_names_from_labels"] == ["docker-compose.yml"]
        assert "C:/fixture/" not in json.dumps(safe)
        negative = command(["inspect", "--type", "container", "--format",
                            "{{.DeliberatelyMissingField}}", identifier], success=False)
        assert negative.returncode != 0
        repeated = command(["inspect", "--type", "container", "--format",
                            binding.FORMAT, identifier]).stdout
        assert json.loads(repeated) == value
        print(json.dumps({"real_docker_template": "passed", "negative_control": "passed",
                          "idempotent_read": "passed", "secret_sentinel_excluded": True,
                          "physical_desktop_test": False, "container_started": False}))
    finally:
        if identifier and binding.ID_RE.fullmatch(identifier):
            label = command(["inspect", "--type", "container", "--format",
                             '{{index .Config.Labels "io.reqsys.fixture"}}', identifier]).stdout.strip()
            if label != "kb-route-binding":
                raise RuntimeError("fixture_cleanup_identity_mismatch")
            command(["rm", identifier])


if __name__ == "__main__":
    main()
