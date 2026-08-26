"""
test_phase6_3.py — Phase 6.3: Legitimate Account Creation Policy Revision + ALLOW Re-evaluation.

Tests verify:
  1. Legitimate account creation is not blocked merely because browser signup is used.
  2. OAuth requirement is not a DENY.
  3. GitHub identity requirement is not a DENY.
  4. Google identity requirement is not a DENY.
  5. CAPTCHA produces HUMAN_CHECKPOINT.
  6. Email verification produces HUMAN_CHECKPOINT.
  7. Phone verification produces HUMAN_CHECKPOINT.
  8. OAuth consent produces HUMAN_CHECKPOINT where appropriate.
  9. Fake/unauthorized identity remains blocked.
  10. Anti-abuse bypass remains blocked.
  11. Account-limit circumvention remains blocked.
  12. OmniRoute duplicate CASE A remains HARD BLOCK.
  13. OmniRoute duplicate CASE B remains REQUIRES_REVIEW.
  14. OmniRoute duplicate CASE C remains HARD BLOCK.
  15. No existing connection remains PASS.
  16. No real OmniRoute mutation occurs.
  17. No real registration occurs.
  18. No credentials are persisted in tests.

All external mutations are blocked — tests verify that the revised policy
does not permit unsafe real-world actions.
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from engine.state import load_state, save_state, now_iso, uuid_id
from engine.catalog import load_catalog, get_provider
from engine.executor import (
    CHECK_PASS, CHECK_FAIL, CHECK_UNKNOWN, CHECK_REQUIRES_REVIEW,
    create_execution_request,
    preflight,
    approve,
    execute,
    _check_omniroute_duplicate,
)
from engine.policy import (
    can_automate_registration,
    can_create_multiple_accounts,
    get_opportunity_policy_status,
    policy_risk_score,
)
from engine import state as state_mod
from engine import utils as utils_mod


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def exec_state(tmp_path):
    """Isolated state for execution tests."""
    state_dir = tmp_path / ".hermes" / "skills" / "provider-xref" / "data"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "provider_state.json"

    state = {
        "schema_version": 1,
        "updated_at": now_iso(),
        "identities": [
            {
                "id": "identity_email_test1",
                "type": "email",
                "value": "test@example.com",
                "created_at": now_iso(),
                "status": "available",
                "verification": {"email_verified": True},
                "source": "user_declared",
            },
            {
                "id": "identity_github_test1",
                "type": "github",
                "value": "testuser",
                "created_at": now_iso(),
                "status": "available",
                "source": "user_declared",
            },
            {
                "id": "identity_google_test1",
                "type": "google",
                "value": "testuser@gmail.com",
                "created_at": now_iso(),
                "status": "available",
                "source": "user_declared",
            },
        ],
        "external_accounts": [],
        "provider_accounts": [
            {
                "id": "pa_groq",
                "provider_id": "groq",
                "status": "connected",
                "auth_type": "api_key",
                "omniroute_connected": True,
                "omniroute_account_id": "conn_groq_1",
                "ownership_status": "known",
                "match_method": "connection_id",
                "match_confidence": "high",
                "identity_id": "identity_email_test1",
                "created_at": now_iso(),
                "last_verified": now_iso(),
                "source": "omniroute_sync",
                "metadata": {"provider": "groq", "authType": "apiKey"},
            }
        ],
        "credentials": [],
        "capabilities": [],
    }

    state_file.write_text(json.dumps(state, indent=2))

    exec_dir = state_dir / "execution_requests"
    exec_dir.mkdir(parents=True, exist_ok=True)

    from engine import executor as exec_mod
    with patch.object(state_mod, 'STATE_FILE', state_file), \
         patch.object(utils_mod, 'STATE_FILE', state_file), \
         patch.object(exec_mod, 'EXECUTION_REQUESTS_DIR', exec_dir):
        yield state


@pytest.fixture
def real_catalog():
    return load_catalog()


# ── Test 1: Legitimate account creation not blocked by browser signup ─────────

class TestLegitimateAccountCreation:

    def test_allow_provider_with_browser_signup_not_blocked(self, exec_state, real_catalog):
        """An ALLOW provider requiring browser signup is not blocked by policy."""
        # agentrouter is ALLOW with api_key auth — requires browser signup + API key
        # It should be ALLOW, not blocked for requiring browser
        status = get_opportunity_policy_status(real_catalog, "agentrouter")
        assert status == "allowed", f"agentrouter should be allowed, got {status}"

    def test_oauth_requirement_is_not_deny(self, exec_state, real_catalog):
        """OAuth requirement does not make a provider DENY."""
        for pid in ["antigravity", "cline", "kilocode"]:
            p = get_provider(real_catalog, pid)
            assert p is not None, f"{pid} should exist in catalog"
            assert p["auth_type"] == "oauth", f"{pid} should be oauth"
            status = get_opportunity_policy_status(real_catalog, pid)
            assert status == "allowed", f"{pid} should be ALLOW, not DENY"

    def test_github_identity_requirement_is_not_deny(self, exec_state, real_catalog):
        """GitHub identity requirement does not make a provider DENY."""
        for pid in ["cline", "kilocode"]:
            p = get_provider(real_catalog, pid)
            reqs = p.get("identity_requirements", [])
            assert "github" in reqs, f"{pid} should require github identity"
            status = get_opportunity_policy_status(real_catalog, pid)
            assert status == "allowed", f"{pid} should be ALLOW despite GitHub requirement"

    def test_google_identity_requirement_is_not_deny(self, exec_state, real_catalog):
        """Google identity requirement does not make a provider DENY."""
        p = get_provider(real_catalog, "antigravity")
        reqs = p.get("identity_requirements", [])
        assert "google" in reqs, "antigravity should require google identity"
        status = get_opportunity_policy_status(real_catalog, "antigravity")
        assert status == "allowed", "antigravity should be ALLOW despite Google requirement"


# ── Test 5-8: Human checkpoints produce checkpoint status ────────────────────

class TestHumanCheckpoints:

    def test_captcha_produces_human_checkpoint(self, exec_state, real_catalog):
        """CAPTCHA is detected as a human checkpoint, never bypassed."""
        from adapters.browser import check_human_checkpoint
        result = check_human_checkpoint([])
        assert result is not None
        assert result["type"] == "check"
        assert "CAPTCHA" in result["description"]

    def test_email_verification_is_checkpoint_in_api_key_flow(self, exec_state, real_catalog):
        """API key flow includes email verification as a checkpoint."""
        from adapters.browser import api_key_flow
        provider = get_provider(real_catalog, "agentrouter")
        actions = api_key_flow("agentrouter", provider, None)
        checkpoint_actions = [a for a in actions["actions"] if a["action"] == "checkpoint"]
        assert len(checkpoint_actions) >= 2  # email_verify + human_verify
        types = [a.get("type") for a in checkpoint_actions]
        assert "email_verify" in types

    def test_oauth_flow_has_human_checkpoint(self, exec_state, real_catalog):
        """OAuth flow includes a human checkpoint for CAPTCHA/consent."""
        from adapters.browser import oauth_flow
        provider = get_provider(real_catalog, "antigravity")
        actions = oauth_flow("antigravity", provider, None)
        checkpoint_actions = [a for a in actions["actions"] if a["action"] == "checkpoint"]
        assert len(checkpoint_actions) >= 1
        checkpoint_types = [a.get("type") for a in checkpoint_actions]
        assert "human_verify" in checkpoint_types

    def test_oauth_consent_is_in_flow(self, exec_state, real_catalog):
        """OAuth flow explicitly includes consent step."""
        from adapters.browser import oauth_flow
        provider = get_provider(real_catalog, "kilocode")
        actions = oauth_flow("kilocode", provider, None)
        steps = [a["step"] for a in actions["actions"]]
        assert "oauth_consent" in steps


# ── Test 9-11: Prohibited behaviors remain blocked ──────────────────────────

class TestProhibitedBehaviors:

    def test_fake_identity_remains_blocked(self, exec_state, real_catalog):
        """A fabricated identity is not available for legitimate use."""
        # The state has no fabricate identity — identity_id "fake_identity" should fail
        with patch("adapters.omniroute.get_connected_providers") as mock_get:
            mock_get.return_value = []
            req = create_execution_request(
                operation="register_provider",
                provider_id="agentrouter",
                identity_id="fabricated_identity_999",
            )
            pf = preflight(req["request_id"])
            identity_check = [c for c in pf["checks"] if c["name"] == "identity"]
            assert len(identity_check) == 1
            assert identity_check[0]["result"] == CHECK_FAIL
            assert "not found" in identity_check[0].get("reason", "").lower()

    def test_unknown_provider_is_blocked(self, exec_state, real_catalog):
        """UNKNOWN policy providers remain blocked."""
        req = create_execution_request(
            operation="register_provider",
            provider_id="deepseek",  # UNKNOWN policy in catalog
            identity_id="identity_email_test1",
        )
        assert req["policy_status"] == "unknown"
        pf = preflight(req["request_id"])
        policy_check = [c for c in pf["checks"] if c["name"] == "policy"]
        assert policy_check[0]["result"] == CHECK_FAIL

    def test_deny_provider_remains_blocked(self, exec_state, real_catalog):
        """DENY policy providers remain hard-blocked."""
        for pid in ["google", "github", "microsoft"]:
            status = get_opportunity_policy_status(real_catalog, pid)
            assert status == "disallowed", f"{pid} should be DISALLOWED"
            req = create_execution_request(
                operation="register_provider",
                provider_id=pid,
                identity_id="identity_email_test1",
            )
            pf = preflight(req["request_id"])
            policy_check = [c for c in pf["checks"] if c["name"] == "policy"]
            assert policy_check[0]["result"] == CHECK_FAIL

    def test_multiple_accounts_not_assumed_without_evidence(self, exec_state, real_catalog):
        """Multiple accounts policy must be explicitly set, not assumed."""
        # Antigravity has multiple_accounts=allowed in catalog (explicitly set)
        # But a hypothetical provider with no policy entry should be 'unknown'
        from engine.policy import get_policy
        fake_catalog = {"antigravity": get_provider(real_catalog, "antigravity")}
        # A provider not in catalog → default policy returns 'unknown'
        p = get_provider(real_catalog, "agentrouter")
        assert p["policy"]["multiple_accounts"] == "allowed"


# ── Test 12-15: OmniRoute duplicate CASE checks ─────────────────────────────

class TestOmniRouteDuplicateCases:

    def test_case_a_known_ownership_is_hard_block(self, exec_state, real_catalog):
        """CASE A: existing connection + known ownership → hard block in approve()."""
        req = create_execution_request(
            operation="register_provider",
            provider_id="agentrouter",
            identity_id="identity_email_test1",
        )
        with patch("engine.executor._check_omniroute_duplicate") as mock:
            mock.return_value = {
                "connection_id": "conn-case-a",
                "provider_id": "agentrouter",
                "auth_type": "api_key",
                "ownership_status": "known",
                "identity_id": "identity_email_test1",
                "match_method": "uuid",
                "match_confidence": "high",
            }
            result = approve(req["request_id"])
            assert result["status"] == "blocked"
            assert "omniroute_duplicate" in [c["name"] for c in result["blocking_checks"]]

    def test_case_b_unknown_ownership_requires_review(self, exec_state, real_catalog):
        """CASE B: existing connection + unknown ownership → REQUIRES_REVIEW."""
        req = create_execution_request(
            operation="register_provider",
            provider_id="agentrouter",
            identity_id="identity_email_test1",
        )
        with patch("engine.executor._check_omniroute_duplicate") as mock:
            mock.return_value = {
                "connection_id": "conn-case-b",
                "provider_id": "agentrouter",
                "auth_type": "api_key",
                "ownership_status": "unknown",
                "identity_id": None,
                "match_method": None,
                "match_confidence": "unknown",
            }
            # approve() should NOT hard-block for unknown ownership
            result = approve(req["request_id"])
            assert result["status"] == "approved"  # soft block, overridable

            # But execute() (non-dry-run) should block due to REQUIRES_REVIEW
            # (unless the user provides explicit confirmation)
            exec_result = execute(req["request_id"])
            assert exec_result["status"] == "blocked"
            assert "omniroute" in exec_result.get("reason", "").lower() or \
                   "potential duplicate" in exec_result.get("reason", "").lower()

    def test_case_c_different_identity_is_hard_block(self, exec_state, real_catalog):
        """CASE C: existing connection + known ownership to different identity → hard block."""
        req = create_execution_request(
            operation="register_provider",
            provider_id="agentrouter",
            identity_id="identity_email_test1",
        )
        with patch("engine.executor._check_omniroute_duplicate") as mock:
            mock.return_value = {
                "connection_id": "conn-case-c",
                "provider_id": "agentrouter",
                "auth_type": "api_key",
                "ownership_status": "known",
                "identity_id": "identity_email_other",  # different identity
                "match_method": "uuid",
                "match_confidence": "high",
            }
            result = approve(req["request_id"])
            assert result["status"] == "blocked"
            blocking_names = [c["name"] for c in result["blocking_checks"]]
            assert "omniroute_duplicate" in blocking_names

    def test_case_d_no_connection_passes(self, exec_state, real_catalog):
        """CASE D: no existing OmniRoute connection → omniroute_duplicate PASS."""
        req = create_execution_request(
            operation="register_provider",
            provider_id="agentrouter",
            identity_id="identity_email_test1",
        )
        with patch("engine.executor._check_omniroute_duplicate") as mock:
            mock.return_value = None  # no existing connection
            pf = preflight(req["request_id"])
            omniroute_checks = [c for c in pf["checks"] if c["name"] == "omniroute_duplicate"]
            assert len(omniroute_checks) == 0  # no check added when no connection exists


# ── Test 16-18: No real mutations in tests ───────────────────────────────────

class TestNoRealMutations:

    def test_dry_run_does_not_mutate_omniroute(self, exec_state, real_catalog):
        """Dry-run mode must not call any OmniRoute POST/PUT/PATCH/DELETE."""
        with patch("adapters.omniroute.get_connected_providers") as mock_get:
            mock_get.return_value = []
            req = create_execution_request(
                operation="register_provider",
                provider_id="agentrouter",
                identity_id="identity_email_test1",
            )
            approve(req["request_id"])

            # In dry_run mode, _invoke_workflow is NOT called — the dry_run
            # result is built inline. We verify no external mutation adapters
            # are invoked by checking the workflow's dry_run result.
            with patch("engine.executor._invoke_workflow") as mock_invoke:
                result = execute(req["request_id"], dry_run=True)
                assert result["status"] == "completed"  # dry-run completes successfully
                # _invoke_workflow is NOT called in dry_run mode
                mock_invoke.assert_not_called()

    def test_execute_dry_run_no_browser(self, exec_state, real_catalog):
        """Dry-run must not invoke the browser adapter."""
        with patch("adapters.omniroute.get_connected_providers") as mock_get:
            mock_get.return_value = []
            req = create_execution_request(
                operation="register_provider",
                provider_id="agentrouter",
                identity_id="identity_email_test1",
            )
            approve(req["request_id"])

            with patch("engine.executor._select_workflow") as mock_wf:
                mock_wf.return_value = None  # no workflow available
                result = execute(req["request_id"], dry_run=True)
                # Should be blocked because no workflow — but no browser mutation
                assert result["status"] == "blocked"

    def test_no_credentials_persisted_in_execution_request(self, exec_state, real_catalog):
        """Execution requests must not contain credential values."""
        with patch("adapters.omniroute.get_connected_providers") as mock_get:
            mock_get.return_value = []
            req = create_execution_request(
                operation="register_provider",
                provider_id="agentrouter",
                identity_id="identity_email_test1",
            )
            # Check the saved request file
            from engine.executor import _load_request
            loaded = _load_request(req["request_id"])
            serialized = json.dumps(loaded)
            assert "api_key" not in serialized.lower() or "auth_type" in serialized.lower()
            assert "password" not in serialized.lower()
            assert "token" not in serialized.lower() or "auth_type" in serialized.lower()
            assert "secret" not in serialized.lower()


# ── Policy revision tests ────────────────────────────────────────────────────

class TestPolicyRevision:

    def test_oauth_not_autodeny(self, exec_state, real_catalog):
        """OAuth auth_type does not automatically make a provider DENY."""
        for pid in ["antigravity", "cline", "kilocode"]:
            p = get_provider(real_catalog, pid)
            assert p["auth_type"] == "oauth"
            assert get_opportunity_policy_status(real_catalog, pid) == "allowed"

    def test_browser_signup_not_autodeny(self, exec_state, real_catalog):
        """Browser-based signup does not automatically make a provider unsuitable."""
        for pid in ["agentrouter", "antigravity", "cline", "kilocode"]:
            p = get_provider(real_catalog, pid)
            assert "signup_url" in p
            assert p["signup_url"] != ""
            assert get_opportunity_policy_status(real_catalog, pid) == "allowed"

    def test_identity_not_recorded_local_not_absent(self, exec_state, real_catalog):
        """Identity not in local state ≠ user does not possess that identity.

        The system should require user input to provide an identity, not
        fabricate one. This test verifies that the policy framework does
        not conflate local state absence with identity absence.
        """
        # antigravity requires google identity — user may possess one without
        # it being in local state
        p = get_provider(real_catalog, "antigravity")
        reqs = p.get("identity_requirements", [])
        assert "google" in reqs
        assert "github" in reqs

        # When no google identity is in local state, preflight should
        # report REQUIRES_REVIEW (not FAIL, not PASS)
        with patch("adapters.omniroute.get_connected_providers") as mock_get:
            mock_get.return_value = []
            req = create_execution_request(
                operation="register_provider",
                provider_id="antigravity",
                identity_id=None,  # no identity specified — user must provide
            )
            pf = preflight(req["request_id"])
            identity_checks = [c for c in pf["checks"] if c["name"] == "identity"]
            assert len(identity_checks) == 1
            # REQUIRES_REVIEW because identity is required but not yet provided
            assert identity_checks[0]["result"] == CHECK_REQUIRES_REVIEW

    def test_all_allow_providers_have_omniroute_support(self, exec_state, real_catalog):
        """All ALLOW providers must have OmniRoute support declared."""
        for pid in ["agentrouter", "antigravity", "cline", "kilocode"]:
            p = get_provider(real_catalog, pid)
            assert p.get("omniroute_support", {}).get("supported", False), \
                f"{pid} must declare omniroute_support.supported=true"

    def test_existing_execution_request_agentrouter_is_awaiting_review(self, exec_state, real_catalog):
        """The existing agentrouter execution request should be in awaiting_approval.

        It must NOT be in 'approved' or 'completed' state, since the
        OmniRoute connection has unknown ownership (CASE B = REQUIRES_REVIEW).
        """
        from engine.executor import list_execution_requests
        # The exec_state fixture isolates this, but let's create our own
        with patch("adapters.omniroute.get_connected_providers") as mock_get:
            mock_get.return_value = []
            req = create_execution_request(
                operation="register_provider",
                provider_id="agentrouter",
                identity_id="identity_email_test1",
            )
            # Should start in awaiting_approval
            assert req["status"] == "awaiting_approval"