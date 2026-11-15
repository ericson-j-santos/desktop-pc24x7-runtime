"""Offline contracts; synthetic OAuth responses are NOT consent or physical evidence."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from unittest.mock import patch

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "lenovo_bridge_device_oauth.py"
spec = importlib.util.spec_from_file_location("lenovo_device_oauth", SOURCE)
oauth = importlib.util.module_from_spec(spec)
assert spec.loader
# Simulate normal script-directory module path for the bridge sibling.
with patch.dict(os.environ):
    import sys
    sys.path.insert(0, str(SOURCE.parent))
    try:
        spec.loader.exec_module(oauth)
    finally:
        sys.path.remove(str(SOURCE.parent))

SHA = "a" * 40


def challenge():
    return {"device_code": "x" * 25, "user_code": "ABCD-EFGH",
            "verification_uri": "https://github.com/login/device", "expires_in": 900, "interval": 5}


def installation(*, permissions=None, selection="selected", app_id=123, owner="ericson-j-santos"):
    return {"id": 45, "app_id": app_id, "account": {"login": owner},
            "permissions": permissions if permissions is not None else dict(oauth.APP_PERMISSIONS),
            "repository_selection": selection, "suspended_at": None}


class Api:
    def __init__(self, inst=None, repos=None):
        self.inst = inst if inst is not None else installation()
        self.repos = repos if repos is not None else [
            {"full_name": "ericson-j-santos/desktop-pc24x7-runtime", "private": False}]
        self.calls = []

    def call(self, method, path):
        self.calls.append((method, path))
        if path == "/user":
            return {"id": oauth.bridge.OWNER_ID, "login": oauth.bridge.OWNER}
        if path == "/user/installations?per_page=100":
            return {"total_count": 1, "installations": [self.inst]}
        if path == "/user/installations/45/repositories?per_page=100":
            return {"total_count": len(self.repos), "repositories": self.repos}
        raise AssertionError("unexpected endpoint")


def test_start_device_flow_validates_endpoint_and_scope():
    calls = []
    def send(endpoint, data):
        calls.append((endpoint, data))
        return challenge()
    assert oauth.start_device_flow("Iv1.test-client", send)["interval"] == 5
    assert calls == [("/login/device/code", {"client_id": "Iv1.test-client", "scope": "offline_access"})]
    with pytest.raises(oauth.bridge.Blocked, match="client_id_invalid"):
        oauth.start_device_flow("bad space", send)


@pytest.mark.parametrize("update", [
    {"verification_uri": "https://evil.example/login/device"},
    {"interval": 1}, {"expires_in": 100000}, {"user_code": "bad.code"},
    {"device_code": "short"}, {"interval": True},
])
def test_challenge_rejects_untrusted_data(update):
    with pytest.raises(oauth.bridge.Blocked, match="challenge_invalid"):
        oauth.start_device_flow("Iv1.test-client", lambda *a: challenge() | update)


def test_poll_authorization_pending_then_user_token_only_in_memory():
    responses = iter([{"error": "authorization_pending"},
                      {"access_token": "ghu_" + "s" * 35, "token_type": "bearer", "expires_in": 28800}])
    clock = [0]
    def pause(seconds):
        clock[0] += seconds
    token = oauth.poll_token("Iv1.test-client", challenge(),
                             lambda *args: next(responses), lambda: clock[0], pause)
    assert token.startswith("ghu_")
    assert clock == [10]


def test_poll_denied_never_returns_token():
    with pytest.raises(oauth.bridge.Blocked, match="denied"):
        oauth.poll_token("Iv1.test-client", challenge(),
                          lambda *args: {"error": "access_denied"}, lambda: 0, lambda s: None)


def test_poll_slow_down_respects_backoff():
    times = [0]
    seen = []
    replies = iter([{"error": "slow_down"},
                    {"access_token": "ghu_" + "t" * 35, "token_type": "bearer", "expires_in": 28800}])
    def pause(seconds):
        seen.append(seconds); times[0] += seconds
    oauth.poll_token("Iv1.test-client", challenge(), lambda *args: next(replies),
                     lambda: times[0], pause)
    assert seen == [5, 10]


def test_scoped_owner_installation_is_accepted():
    api = Api()
    oauth.verify_restricted_installation(api, 123)
    assert api.calls[-1] == ("GET", "/user/installations/45/repositories?per_page=100")


@pytest.mark.parametrize("inst,repos", [
    (installation(selection="all"), None),
    (installation(app_id=999), None),
    (installation(owner="not-owner"), None),
    (installation(permissions={"actions": "write"}), None),
    (installation(permissions=dict(oauth.APP_PERMISSIONS, administration="write")), None),
    (None, [{"full_name": "other/repository", "private": False}]),
    (None, [{"full_name": "ericson-j-santos/desktop-pc24x7-runtime", "private": False},
            {"full_name": "someone/other", "private": False}]),
])
def test_bad_scopes_rejected(inst, repos):
    api = Api(inst=inst, repos=repos)
    with pytest.raises(oauth.bridge.Blocked):
        oauth.verify_restricted_installation(api, 123)


def test_dispatch_cannot_start_without_signed_ticket():
    with pytest.raises(oauth.bridge.Blocked, match="signed_ticket"):
        oauth.invoke_bridge("dispatch", SHA, "ghu_" + "z" * 30)


def test_ephemeral_token_restored_even_when_bridge_raises():
    token = "ghu_" + "z" * 40
    with patch.dict(os.environ, {"REQSYS_GITHUB_APP_USER_TOKEN": "old-token"}):
        with patch.object(oauth.bridge, "main", side_effect=RuntimeError("simulate")):
            with pytest.raises(RuntimeError):
                oauth.invoke_bridge("preflight", SHA, token)
        assert os.environ["REQSYS_GITHUB_APP_USER_TOKEN"] == "old-token"


def test_no_tty_denies_before_network():
    with patch.object(oauth.sys.stdin, "isatty", return_value=False):
        assert oauth.main(["preflight", "--client-id", "Iv1.test-client", "--app-id", "123", "--sha", SHA]) == 3
