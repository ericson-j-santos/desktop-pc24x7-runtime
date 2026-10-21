"""Synthetic-only crypto proof tests. No real credentials, hosts or databases."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
FILE = SCRIPTS / "pc24x7_todo_custody_preflight.py"
spec = importlib.util.spec_from_file_location("custody_preflight_test", FILE)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


@pytest.fixture(scope="module")
def keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    def material(k):
        return (k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
                k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return material(key), material(other)


@pytest.fixture
def material(tmp_path, keys):
    tmp_path.chmod(0o700)
    issuer = tmp_path/"issuer"; issuer.mkdir(mode=0o700)
    recovery = tmp_path/"recovery"; recovery.mkdir(mode=0o700)
    public_file = tmp_path/"public.pem"; public_file.write_bytes(keys[0][0]); public_file.chmod(0o600)
    identity_file = tmp_path/"identity.pem"; identity_file.write_bytes(keys[0][1]); identity_file.chmod(0o600)
    different = tmp_path/"different.pem"; different.write_bytes(keys[1][1]); different.chmod(0o600)
    if os.name == "nt":
        from backup_reqsys_current_dev_postgres import owner_sid, private_acl
        sid = owner_sid()
        for p in (issuer, recovery, identity_file, different):
            private_acl(p, sid)
    return {"issuer":issuer, "recovery":recovery, "public":public_file,
            "identity":identity_file,"different":different}


def proof(m, *, at=None):
    issued=c.issue(m["issuer"],m["public"],"synthetic-proof",at=at)
    response=m["recovery"]/"response.json"
    answered=c.answer(m["issuer"]/"challenge.json", response, m["identity"], issued["challenge_sha256"],at=at)
    verified=c.verify(m["issuer"]/"challenge.json",m["issuer"]/"issuer-receipt.json",response,at=at)
    return issued,answered,verified,response


def test_offhost_simulation_proves_key_possession_but_not_independent_custody(material):
    issued,answered,verified,_=proof(material)
    assert issued["state"]=="issued"
    assert answered["state"]=="answered"
    assert verified["state"]=="key_possession_verified"
    assert verified["cryptographic_match"] and not verified["offhost_custody_verified"]
    assert not verified["cutover_ready"]
    assert issued["recipient_sha256"]==verified["recipient_sha256"]


def test_exact_replay_preserves_all_files_and_no_extra_challenges(material):
    issued,answered,verified,response=proof(material)
    files=[material["issuer"]/"challenge.json", material["issuer"]/"issuer-receipt.json", response]
    copies=[(p.read_bytes(),p.stat().st_mtime_ns) for p in files]
    assert c.issue(material["issuer"],material["public"],"synthetic-proof")["state"]=="already_issued"
    assert c.answer(files[0],response,material["identity"],issued["challenge_sha256"])["state"]=="already_answered"
    assert c.verify(files[0],files[1],files[2])==verified
    assert [(p.read_bytes(),p.stat().st_mtime_ns) for p in files]==copies


def test_wrong_key_rejected_without_response(material):
    issued=c.issue(material["issuer"],material["public"],"synthetic-proof")
    response=material["recovery"]/"response.json"
    with pytest.raises(c.CustodyBlocked,match="IDENTITY_RECIPIENT_MISMATCH"):
        c.answer(material["issuer"]/"challenge.json",response,material["different"],issued["challenge_sha256"])
    assert not response.exists()


def test_untrusted_digest_rejected_before_private_key_read(material):
    issued=c.issue(material["issuer"],material["public"],"synthetic-proof")
    wrong=material["recovery"]/"response.json"
    with pytest.raises(c.CustodyBlocked,match="TRUSTED_CHALLENGE_DIGEST_REQUIRED"):
        c.answer(material["issuer"]/"challenge.json",wrong,material["identity"],"bad")
    with pytest.raises(c.CustodyBlocked,match="CHALLENGE_HASH_MISMATCH"):
        c.answer(material["issuer"]/"challenge.json",wrong,material["identity"],"a"*64)
    assert not wrong.exists()


def test_modified_challenge_rejected_by_independent_hash(material):
    issued=c.issue(material["issuer"],material["public"],"synthetic-proof")
    path=material["issuer"]/"challenge.json"
    doc=json.loads(path.read_text(encoding="utf-8"));doc["correlation_id"]="tampered"
    path.write_bytes(c.stable_json(doc))
    with pytest.raises(c.CustodyBlocked,match="CHALLENGE_HASH_MISMATCH"):
        c.answer(path,material["recovery"]/"response.json",material["identity"],issued["challenge_sha256"])


def test_expired_and_future_challenge_block_before_secret_access(material):
    start=datetime.now(timezone.utc).replace(microsecond=0)
    issued=c.issue(material["issuer"],material["public"],"synthetic-proof",at=start)
    with pytest.raises(c.CustodyBlocked,match="EXPIRED_OR_FUTURE"):
        c.answer(material["issuer"]/"challenge.json",material["recovery"]/"response.json",material["identity"],issued["challenge_sha256"],at=start+timedelta(minutes=16))
    with pytest.raises(c.CustodyBlocked,match="EXPIRED_OR_FUTURE"):
        c.verify(material["issuer"]/"challenge.json",material["issuer"]/"issuer-receipt.json",material["recovery"]/"absent",at=start+timedelta(minutes=16))
    with pytest.raises(c.CustodyBlocked,match="EXPIRED_OR_FUTURE"):
        c.answer(material["issuer"]/"challenge.json",material["recovery"]/"response.json",material["identity"],issued["challenge_sha256"],at=start-timedelta(seconds=31))


def test_tampered_proof_rejected(material):
    _,_,_,response=proof(material)
    info=json.loads(response.read_text(encoding="utf-8"))
    info["proof_hmac_sha256"]="1"*64
    response.write_bytes(c.stable_json(info))
    with pytest.raises(c.CustodyBlocked,match="PROOF_MISMATCH"):
        c.verify(material["issuer"]/"challenge.json",material["issuer"]/"issuer-receipt.json",response)


def test_partial_issue_blocks_idempotent_retries(material):
    (material["issuer"]/"challenge.json").write_bytes(b"partial")
    with pytest.raises(c.CustodyBlocked,match="PARTIAL_ISSUE_REQUIRES_REVIEW"):
        c.issue(material["issuer"],material["public"],"synthetic-proof")
    assert not (material["issuer"]/"issuer-receipt.json").exists()


def test_wrong_issuer_correlation_is_blocked_on_replay(material):
    c.issue(material["issuer"],material["public"],"synthetic-proof")
    with pytest.raises(c.CustodyBlocked,match="EXISTING_CHALLENGE_MISMATCH"):
        c.issue(material["issuer"],material["public"],"other-correlation")


def test_symlink_to_private_identity_blocked(material):
    issued=c.issue(material["issuer"],material["public"],"synthetic-proof")
    link=material["recovery"]/"identity-link.pem"
    try: link.symlink_to(material["identity"])
    except (OSError,NotImplementedError): pytest.skip("symlinks unavailable without privilege")
    with pytest.raises(c.CustodyBlocked,match="LINK_PATH_FORBIDDEN"):
        c.answer(material["issuer"]/"challenge.json",material["recovery"]/"response.json",link,issued["challenge_sha256"])


@pytest.mark.skipif(os.name=="nt",reason="POSIX modes; Windows validates owner-only ACL in existing module")
def test_world_readable_identity_rejected(material):
    issued=c.issue(material["issuer"],material["public"],"synthetic-proof")
    material["identity"].chmod(0o644)
    with pytest.raises(c.CustodyBlocked,match="PRIVATE_PERMISSIONS_REQUIRED"):
        c.answer(material["issuer"]/"challenge.json",material["recovery"]/"response.json",material["identity"],issued["challenge_sha256"])


def test_wrong_response_cannot_be_reused_for_another_challenge(material):
    first,_,_,response=proof(material)
    other=material["recovery"]/"other";other.mkdir(mode=0o700)
    if os.name == "nt":
        from backup_reqsys_current_dev_postgres import owner_sid, private_acl, assert_private_acl
        private_acl(other, owner_sid())
        assert_private_acl(other, owner_sid())
    issued2=c.issue(other,material["public"],"second-challenge")
    with pytest.raises(c.CustodyBlocked,match="RESPONSE_INVALID"):
        c.verify(other/"challenge.json",other/"issuer-receipt.json",response)
    assert issued2["challenge_sha256"]!=first["challenge_sha256"]


def test_weak_rsa_key_rejected_before_issue(material):
    weak=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    material["public"].write_bytes(weak.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(c.CustodyBlocked,match="RSA_KEY_POLICY_INVALID"):
        c.issue(material["issuer"],material["public"],"synthetic-proof")
    assert list(material["issuer"].iterdir())==[]


def test_json_duplicate_properties_rejected():
    with pytest.raises(c.CustodyBlocked,match="DUPLICATE_JSON_KEY"):
        c.parse_json(b'{"x":1,"x":2}')


def test_cli_full_protocol_with_secret_free_stdout(material):
    def call(*args,env=None):
        p=subprocess.run([sys.executable,str(FILE),*map(str,args)],env=env,capture_output=True,text=True,timeout=20)
        return p.returncode,json.loads(p.stdout),p.stderr
    env={**os.environ,"TODO_RECOVERY_RECIPIENT_FILE":str(material["public"]),"TODO_RECOVERY_IDENTITY_FILE":str(material["identity"])}
    rc,issued,stderr=call("issue","--challenge-dir",material["issuer"],"--correlation-id","synthetic-cli",env=env)
    assert rc==0 and issued["state"]=="issued" and stderr==""
    rc,answered,stderr=call("answer","--challenge",material["issuer"]/"challenge.json","--response",material["recovery"]/"response.json","--expected-challenge-sha256",issued["challenge_sha256"],env=env)
    assert rc==0 and answered["state"]=="answered" and stderr==""
    rc,verified,stderr=call("verify","--challenge",material["issuer"]/"challenge.json","--issuer-receipt",material["issuer"]/"issuer-receipt.json","--response",material["recovery"]/"response.json",env=env)
    assert rc==0 and verified["state"]=="key_possession_verified" and stderr==""
    for value in (issued,answered,verified):
        text=json.dumps(value)
        assert "BEGIN PRIVATE KEY" not in text and "ciphertext_b64" not in text
        assert value["offhost_custody_verified"] is False and value["cutover_ready"] is False


def test_cli_no_real_key_reference_blocks_without_side_effects(material):
    env={k:v for k,v in os.environ.items() if not k.startswith("TODO_RECOVERY_")}
    p=subprocess.run([sys.executable,str(FILE),"issue","--challenge-dir",str(material["issuer"]),"--correlation-id","synthetic-cli"],env=env,capture_output=True,text=True,timeout=20)
    assert p.returncode==2 and json.loads(p.stdout)["reason"]=="ISSUE_INPUT_REQUIRED"
    assert list(material["issuer"].iterdir())==[]


def test_code_does_not_issue_credentials_or_touch_network_or_database():
    text=FILE.read_text(encoding="utf-8")
    for marker in ("generate_private_key(","get_connection_string", "requests.","urllib.","subprocess.","pg_dump", "pg_restore", "ssh ", "shell=True"):
        assert marker not in text
    assert "cutover_ready\": False" in text
    assert 'choices=("issue", "answer", "verify")' in text


def test_boundaries_must_match_portable_sealed_format():
    assert c.MAGIC==b"TODO-PG-SEALED-V1\0"
    assert c.recipient_id(rsa.generate_private_key(public_exponent=65537,key_size=3072)).__len__()==64


def test_existing_challenge_rejects_rotated_public_key(material,keys):
    c.issue(material["issuer"],material["public"],"synthetic-proof")
    material["public"].write_bytes(keys[1][0])
    with pytest.raises(c.CustodyBlocked,match="EXISTING_CHALLENGE_MISMATCH"):
        c.issue(material["issuer"],material["public"],"synthetic-proof")


def test_rejects_nonprivate_response_directory_before_identity_read(material):
    issued=c.issue(material["issuer"],material["public"],"synthetic-proof")
    material["recovery"].chmod(0o777)
    if os.name == "nt":pytest.skip("ACL must be controlled by Windows owner-only helper")
    with pytest.raises(c.CustodyBlocked,match="PRIVATE_PERMISSIONS_REQUIRED"):
        c.answer(material["issuer"]/"challenge.json",material["recovery"]/"response.json",material["identity"],issued["challenge_sha256"])


def test_existing_corrupt_receipt_rejected(material):
    c.issue(material["issuer"],material["public"],"synthetic-proof")
    (material["issuer"]/"issuer-receipt.json").write_bytes(b'{"bad":"value"}')
    with pytest.raises(c.CustodyBlocked,match="EXISTING_CHALLENGE_MISMATCH"):
        c.issue(material["issuer"],material["public"],"synthetic-proof")


def test_key_fingerprint_matches_existing_sealed_format(material):
    import pc24x7_todo_sealed as sealed
    public=serialization.load_pem_public_key(material["public"].read_bytes())
    assert sealed.key_id(public)==c.recipient_id(public)
    public_key=serialization.load_pem_public_key(material["public"].read_bytes())
    private_key=serialization.load_pem_private_key(material["identity"].read_bytes(),password=None)
    ciphertext=public_key.encrypt(b"synthetic-interoperability",c.oaep())
    assert private_key.decrypt(ciphertext,sealed.oaep())==b"synthetic-interoperability"
