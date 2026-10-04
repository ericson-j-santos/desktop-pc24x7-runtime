#!/usr/bin/env python3
"""Read-only proposal for one owner exception file DACL; no apply route."""
from __future__ import annotations
import argparse
import ctypes
import importlib.util
import json
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location(
    "_owner_registry_acl_plan", Path(__file__).with_name("register_reqsys_dev_owner_actions.py")
)
registry = importlib.util.module_from_spec(SPEC)
_no_bytecode = sys.dont_write_bytecode
try:
    sys.dont_write_bytecode = True
    SPEC.loader.exec_module(registry)
finally:
    sys.dont_write_bytecode = _no_bytecode

def read_security(path, private):
    registry.no_reparse(path)
    if not path.is_file():
        raise registry.OperationError("fixed_configuration_file_required")
    size = registry.wintypes.DWORD()
    private.adv.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(size))
    if not size.value or size.value > 65536:
        raise registry.OperationError("configuration_acl_unavailable")
    descriptor = ctypes.create_string_buffer(size.value)
    if not private.adv.GetFileSecurityW(str(path), 5, descriptor, size.value, ctypes.byref(size)):
        raise registry.OperationError("configuration_acl_unavailable")
    text = ctypes.c_void_p()
    if not private.adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor, 1, 5, ctypes.byref(text), None
    ):
        raise registry.OperationError("configuration_acl_unavailable")
    try:
        return ctypes.wstring_at(text)
    finally:
        private.kernel.LocalFree(text)

def build_plan(sddl, private):
    observation = private._safe_acl_observation(sddl)
    if not observation.get("descriptor_recognized") or not observation.get("counts_complete"):
        raise registry.OperationError("configuration_acl_observation_incomplete")
    if observation["owner_category"] not in ("current_user", "administrators"):
        raise registry.OperationError("configuration_acl_owner_not_current_user_or_administrators")
    if not observation["current_user_allow_present"]:
        raise registry.OperationError("configuration_acl_current_user_effective_access_missing")
    target_dacl = f"D:P(A;;FA;;;{private.sid})(A;;FA;;;SY)"
    proof = {
        "contract": "owner-risk3-single-file-acl-repair-plan-v1",
        "fixed_target": "owner-risk3-exceptions.local.json",
        "before_acl_sha256": registry.sha256_bytes(sddl.encode("utf-8")),
        "proposed_dacl_sha256": registry.sha256_bytes(target_dacl.encode("utf-8")),
        "preserve_owner": True,
    }
    return {
        "status": "planned", "read_only": True, "approval_required": True,
        "apply_available": False, "plan_sha256": registry.sha256_bytes(registry.canonical(proof)),
        "target_kind": "single_owner_exception_file",
        "before_acl": observation,
        "proposed_acl": {
            "owner_preserved": True, "dacl_protected": True,
            "allowed_principal_categories": ["current_user", "system"],
        },
        "configuration_bytes_read": False, "configuration_bytes_changed": False,
        "parent_or_audit_acl_changed": False, "grants_changed": False,
        "private_dpapi_backup_required_before_apply": True,
    }

def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        registry.require_owner()
        private = registry.WindowsPrivateFiles()
        path = registry.CONFIG_ROOT / registry.CONFIG_NAME
        evidence = build_plan(read_security(path, private), private)
    except Exception as exc:
        code = exc.code if isinstance(exc, registry.OperationError) else "acl_repair_plan_failed"
        print(json.dumps({"status": "blocked", "code": code}, sort_keys=True))
        return 2
    print(json.dumps(evidence, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
