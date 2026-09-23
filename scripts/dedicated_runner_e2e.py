#!/usr/bin/env python3
"""Prova E2E independente do runner dedicado do Desktop Runtime."""
from __future__ import annotations
import argparse
import json
import os
import socket
from pathlib import Path

EXPECTED_HOST = "DESKTOP-PDQK954"
EXPECTED_REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
EXPECTED_RUNNER = "DESKTOP-PDQK954-runtime"


def build_evidence() -> dict:
    host = socket.gethostname()
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    runner = os.environ.get("RUNNER_NAME", "")
    runner_os = os.environ.get("RUNNER_OS", "")
    runner_arch = os.environ.get("RUNNER_ARCH", "")
    sha = os.environ.get("GITHUB_SHA", "")
    ok = (
        host.casefold() == EXPECTED_HOST.casefold()
        and repo == EXPECTED_REPOSITORY
        and runner == EXPECTED_RUNNER
        and runner_os.casefold() == "windows"
        and runner_arch.casefold() == "x64"
        and len(sha) == 40
    )
    return {
        "ok": ok,
        "host": host,
        "repository": repo,
        "runner_name": runner,
        "runner_os": runner_os,
        "runner_arch": runner_arch,
        "source_sha": sha,
        "production_touched": False,
        "secrets_read": False,
        "reboot_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-file", type=Path, required=True)
    args = parser.parse_args()
    evidence = build_evidence()
    args.evidence_file.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_file.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["ok"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
