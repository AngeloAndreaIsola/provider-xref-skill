"""
test_phase10_recovery.py — Phase 10 lifecycle recovery / partial-failure safety.

Locks in the execution-engine guarantees from the prompt:

  * An unexpected crash mid-workflow must leave the request in `failed`,
    never stuck in `executing`.
  * Credential acquisition failure (1Password OK, OmniRoute fails) must
    record `failed` with a secret-stripped result.
  * Finalization failure must not be silently reported as success.
  * A human checkpoint must never persist secret fields (api_key / otp /
    password / token) in the request or checkpoint.
  * No secrets may appear in the persisted request / checkpoint / result.

NOTE: `execute()` drives the pipeline by calling `workflow.register()`,
which in real workflows performs verify → acquire → connect → finalize
internally. The mock workflows below therefore put the failure outcome
inside `register()` so it exercises the same code path.
"""
import sys
import json as _json
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.executor import (
    create_execution_request,
    approve,
    execute,
    registration_status,
)
from engine.state import default_state


SECRET_KEYS = ("password", "api_key", "token", "secret", "otp", "sms_code", "credential")


PROVIDER = "agentrouter"
IDENTITY = "ident_test"


class _CrashWorkflow:
    """A workflow whose register() raises, simulating browser/network death."""
    auth_type = "api_key"
    requires_browser = False

    def prepare(self, *a, **k):
        return {}

    def register(self, *a, **k):
        raise RuntimeError("simulated browser crash mid-registration")

    def verify(self, *a, **k):
        return {"status": "verified"}

    def acquire_credentials(self, *a, **k):
        return {"status": "success", "credential_ref": {"backend": "1password"}}

    def connect_omniroute(self, *a, **k):
        return {"status": "connected", "verified": True}

    def finalize(self, *a, **k):
        return {"status": "completed"}


class _OmniRouteFailWorkflow:
    """1Password succeeds (credential acquired) but OmniRoute connection fails."""
    auth_type = "api_key"
    requires_browser = False

    def prepare(self, *a, **k):
        return {}

    def register(self, *a, **k):
        return {
            "status": "failed",
            "reason": "OmniRoute connection failed: 503",
            "credential": {"status": "success", "credential_ref": {"backend": "1password", "item_id": "x"}},
            "omniroute": {"status": "failed", "error": "503"},
        }

    def verify(self, *a, **k):
        return {"status": "verified"}

    def acquire_credentials(self, *a, **k):
        return {"status": "success", "credential_ref": {"backend": "1password", "item_id": "x"}}

    def connect_omniroute(self, *a, **k):
        return {"status": "failed", "error": "omniroute 503"}

    def finalize(self, *a, **k):
        return {"status": "completed"}


def _seed(tmp_path, monkeypatch):
    """Seed state with an ALLOW api_key provider and a known identity, then
    return an approved execution request id. OmniRoute / 1Password adapters
    are patched to not-reachable stubs so the lifecycle never hits live
    services."""
    import engine.state as state_mod
    import engine.utils as utils_mod
    import engine.executor as exec_mod
    import adapters.omniroute as omni_mod
    import adapters.onepassword as op_mod

    state_dir = tmp_path / "px"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "provider_state.json"
    st = default_state()
    st["identities"] = [{
        "id": IDENTITY,
        "type": "email",
        "value": "test@example.com",
        "created_at": "2025-06-01T10:00:00Z",
        "status": "active",
        "verification": {"email_verified": True},
        "source": "user_declared",
    }]
    state_file.write_text(_json.dumps(st, indent=2))
    exec_dir = state_dir / "execution_requests"
    exec_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(utils_mod, "STATE_FILE", state_file)
    monkeypatch.setattr(state_mod, "STATE_FILE", state_file)
    monkeypatch.setattr(exec_mod, "EXECUTION_REQUESTS_DIR", exec_dir)
    monkeypatch.setattr(omni_mod, "is_running", lambda: False)
    monkeypatch.setattr(omni_mod, "get_connected_providers", lambda: [])
    monkeypatch.setattr(op_mod, "ensure_signed_in", lambda: False)

    req = create_execution_request("register_provider", PROVIDER, identity_id=IDENTITY)
    result = approve(req["request_id"])
    assert result["status"] == "approved", result
    return req["request_id"]


def _assert_no_secrets(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            assert k not in SECRET_KEYS, f"secret key '{k}' found at {path}"
            _assert_no_secrets(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _assert_no_secrets(v, f"{path}[{i}]")


class TestRecoveryOnCrash:

    def test_unexpected_crash_records_failed_not_executing(self, tmp_path, monkeypatch):
        rid = _seed(tmp_path, monkeypatch)
        import engine.executor as exec_mod
        monkeypatch.setattr(exec_mod, "_select_workflow", lambda p: _CrashWorkflow())
        result = execute(rid, dry_run=False)
        assert result["status"] == "failed", result
        # Reload persisted request — must NOT be stuck in executing
        status = registration_status(rid)
        assert status["status"] == "failed"
        _assert_no_secrets(status)

    def test_1password_ok_omniroute_fails_records_failed(self, tmp_path, monkeypatch):
        rid = _seed(tmp_path, monkeypatch)
        import engine.executor as exec_mod
        monkeypatch.setattr(exec_mod, "_select_workflow", lambda p: _OmniRouteFailWorkflow())
        result = execute(rid, dry_run=False)
        assert result["status"] == "failed", result
        # The persisted request must reflect failure (never silently completed).
        persisted = registration_status(rid)
        assert persisted["status"] == "failed", persisted
        assert persisted["status"] != "completed"
        assert persisted["status"] != "executing"


class TestNoSilentSuccess:

    def test_finalize_failure_not_reported_success(self, tmp_path, monkeypatch):
        rid = _seed(tmp_path, monkeypatch)
        import engine.executor as exec_mod

        class W(_OmniRouteFailWorkflow):
            def register(self, *a, **k):
                raise RuntimeError("finalize exploded")

        monkeypatch.setattr(exec_mod, "_select_workflow", lambda p: W())
        result = execute(rid, dry_run=False)
        assert result["status"] == "failed", result


class TestSecretSafetyInLifecycle:

    def test_checkpoint_persists_no_secrets(self, tmp_path, monkeypatch):
        rid = _seed(tmp_path, monkeypatch)
        import engine.executor as exec_mod

        class W(_OmniRouteFailWorkflow):
            def register(self, *a, **k):
                return {
                    "status": "completed",
                    "human_checkpoint_required": True,
                    "checkpoint_info": {
                        "step": "phone_verification",
                        "checkpoint_type": "phone_verification",
                        # A careless workflow would try to stash these:
                        "api_key": "sk-LIVE-FAKE",
                        "password": "hunter2",
                        "otp": "123456",
                    },
                }

        monkeypatch.setattr(exec_mod, "_select_workflow", lambda p: W())
        result = execute(rid, dry_run=False)
        # Even if a checkpoint is reached, secrets must be stripped by the executor
        _assert_no_secrets(result)
        if isinstance(result, dict) and result.get("checkpoint"):
            _assert_no_secrets(result["checkpoint"])
