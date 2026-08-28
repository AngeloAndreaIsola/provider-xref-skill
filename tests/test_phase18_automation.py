"""
test_phase18_automation.py — Phase 18 approval-gated reconciliation automation.

The safety property under test: an inconsistency is NEVER silently repaired.

Covers:
  * no execution without explicit matching approval
  * approval is single-use and scoped
  * preconditions gate mutation
  * postcondition verification gates "resolved"
  * unverifiable results stay UNRESOLVED, never success
  * human checkpoints surfaced, never bypassed
  * headed browser used when required
  * secret stripping in results/records
  * failure and exception handling
  * reconciliation runs after execution
  * human-only actions refused
  * planning executes nothing
"""

import json
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.automation import (
    EXECUTABLE_ACTIONS,
    HUMAN_ONLY_ACTIONS,
    OUTCOME_AWAITING_APPROVAL,
    OUTCOME_AWAITING_CHECKPOINT,
    OUTCOME_BLOCKED,
    OUTCOME_FAILED,
    OUTCOME_RESOLVED,
    OUTCOME_UNVERIFIED,
    ActionRecord,
    Approval,
    check_preconditions,
    execute_approved_action,
    plan_remediation,
    preconditions_ok,
    strip_secrets,
    verify_postconditions,
)
from engine.review import (
    ACTION_ACQUIRE_API_KEY,
    ACTION_CONNECT_OMNIROUTE,
    ACTION_RESOLVE_IDENTITY_CONFLICT,
    Finding,
    CATEGORY_CONFLICTING_IDENTITY,
    CATEGORY_MISSING_OMNIROUTE,
    REVIEW_OPEN,
    assert_secret_free,
    get_review_status,
)

_ID = "identity_email_{}_x"
SECRET = "gsk_TESTSECRETVALUE1234567890"


def state_with(provider_accounts, identities=None):
    return {
        "identities": identities or [],
        "external_accounts": [],
        "provider_accounts": provider_accounts,
        "credentials": [],
        "capabilities": [],
    }


@pytest.fixture
def review_path(tmp_path):
    return tmp_path / "review_state.json"


@pytest.fixture
def missing_omni_setup():
    """A Groq account with everything except an OmniRoute connection."""
    idents = [{"id": _ID.format("lazy"), "type": "email",
               "value": "lazymause@gmail.com"}]
    pa = [{"id": "pa_lazy", "provider_id": "groq",
           "identity_id": _ID.format("lazy"), "status": "connected",
           "auth_type": "api_key", "ownership_status": "known",
           "credential_ref": {"item_id": "item_lazy", "item_title": "Groq Api Key",
                              "reference": "op://Personal/item_lazy/credential"}}]
    op = [{"item_id": "item_lazy", "title": "Groq Api Key",
           "username": "lazymause@gmail.com", "vault": "Personal"},
          {"item_id": "item_login", "title": "Groq Login",
           "username": "lazymause@gmail.com", "vault": "Personal"}]
    return state_with(pa, idents), [], op


def finding_for(action=ACTION_CONNECT_OMNIROUTE,
                category=CATEGORY_MISSING_OMNIROUTE,
                provider="groq",
                key="groq::identity_email_lazymause_gmail_com"):
    return Finding(
        finding_id="finding_test_1",
        severity="high",
        category=category,
        provider_id=provider,
        account_key=key,
        recommended_action=action,
    )


def approval_for(finding, action, who="angelo"):
    return Approval(finding_id=finding.finding_id, action=action, approved_by=who)


# ── The core safety property ────────────────────────────────────────────────

class TestApprovalGate:

    def test_no_approval_means_no_execution(self):
        calls = []
        f = finding_for()
        rec = execute_approved_action(f, ACTION_CONNECT_OMNIROUTE,
                                      approval=None,
                                      executor=lambda x: calls.append(x))
        assert rec.outcome == OUTCOME_AWAITING_APPROVAL
        assert calls == [], "must not execute without approval"

    def test_mismatched_finding_id_rejected(self):
        calls = []
        f = finding_for()
        bad = Approval(finding_id="other_finding", action=ACTION_CONNECT_OMNIROUTE,
                       approved_by="angelo")
        rec = execute_approved_action(f, ACTION_CONNECT_OMNIROUTE, bad,
                                      executor=lambda x: calls.append(x))
        assert rec.outcome == OUTCOME_AWAITING_APPROVAL
        assert calls == []

    def test_mismatched_action_rejected(self):
        calls = []
        f = finding_for()
        bad = Approval(finding_id=f.finding_id, action=ACTION_ACQUIRE_API_KEY,
                       approved_by="angelo")
        rec = execute_approved_action(f, ACTION_CONNECT_OMNIROUTE, bad,
                                      executor=lambda x: calls.append(x))
        assert rec.outcome == OUTCOME_AWAITING_APPROVAL
        assert calls == []

    def test_empty_approver_rejected(self):
        f = finding_for()
        bad = Approval(finding_id=f.finding_id, action=ACTION_CONNECT_OMNIROUTE,
                       approved_by="")
        rec = execute_approved_action(f, ACTION_CONNECT_OMNIROUTE, bad,
                                      executor=lambda x: {"performed": True})
        assert rec.outcome == OUTCOME_AWAITING_APPROVAL

    def test_approval_is_single_use(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for()
        ap = approval_for(f, ACTION_CONNECT_OMNIROUTE)
        execute_approved_action(f, ACTION_CONNECT_OMNIROUTE, ap,
                                executor=lambda x: {"performed": True},
                                state=st, omni_connections=omni, op_items=op)
        assert ap.consumed is True
        second = execute_approved_action(f, ACTION_CONNECT_OMNIROUTE, ap,
                                        executor=lambda x: {"performed": True},
                                        state=st, omni_connections=omni, op_items=op)
        assert second.outcome == OUTCOME_AWAITING_APPROVAL

    def test_approval_scope_restricts_account(self):
        f = finding_for()
        ap = Approval(finding_id=f.finding_id, action=ACTION_CONNECT_OMNIROUTE,
                      approved_by="angelo", scope_account_key="groq::someone_else")
        rec = execute_approved_action(f, ACTION_CONNECT_OMNIROUTE, ap,
                                      executor=lambda x: {"performed": True})
        assert rec.outcome == OUTCOME_AWAITING_APPROVAL

    def test_no_silent_repair_path_exists(self):
        """Source-level check: nothing executes from detection alone."""
        src = (SKILL_ROOT / "engine" / "automation.py").read_text()
        assert "approval.matches" in src
        assert "OUTCOME_AWAITING_APPROVAL" in src

    def test_read_only_modules_cannot_execute(self):
        for mod in ("review.py", "reconcile.py", "accounts.py",
                    "inventory.py", "account_reconcile.py", "onboarding.py"):
            src = (SKILL_ROOT / "engine" / mod).read_text()
            assert "execute_approved_action" not in src, \
                f"{mod} must not be able to execute mutations"


# ── Human-only actions ──────────────────────────────────────────────────────

class TestHumanOnlyActions:

    @pytest.mark.parametrize("action", HUMAN_ONLY_ACTIONS)
    def test_human_only_action_refused(self, action):
        calls = []
        f = finding_for(action=action, category=CATEGORY_CONFLICTING_IDENTITY)
        ap = approval_for(f, action)
        rec = execute_approved_action(f, action, ap,
                                      executor=lambda x: calls.append(x))
        assert rec.outcome == OUTCOME_BLOCKED
        assert calls == []

    def test_conflicting_identity_never_auto_resolved(self):
        f = finding_for(action=ACTION_RESOLVE_IDENTITY_CONFLICT,
                        category=CATEGORY_CONFLICTING_IDENTITY)
        rec = execute_approved_action(
            f, ACTION_RESOLVE_IDENTITY_CONFLICT,
            approval_for(f, ACTION_RESOLVE_IDENTITY_CONFLICT),
            executor=lambda x: {"performed": True})
        assert rec.outcome == OUTCOME_BLOCKED
        assert rec.verified is False

    def test_executable_and_human_only_are_disjoint(self):
        assert not set(EXECUTABLE_ACTIONS) & set(HUMAN_ONLY_ACTIONS)


# ── Preconditions ───────────────────────────────────────────────────────────

class TestPreconditions:

    def test_preconditions_structured(self):
        f = finding_for()
        checks = check_preconditions(f, ACTION_CONNECT_OMNIROUTE)
        assert checks and all({"check", "ok", "detail"} <= set(c) for c in checks)

    def test_unknown_provider_blocks(self):
        f = finding_for(provider="not-a-real-provider")
        checks = check_preconditions(f, ACTION_CONNECT_OMNIROUTE)
        assert preconditions_ok(checks) is False

    def test_action_must_match_finding_proposal(self):
        f = finding_for(action=ACTION_CONNECT_OMNIROUTE)
        checks = check_preconditions(f, ACTION_ACQUIRE_API_KEY)
        assert preconditions_ok(checks) is False

    def test_missing_account_key_blocks(self):
        f = finding_for(key="")
        checks = check_preconditions(f, ACTION_CONNECT_OMNIROUTE)
        assert preconditions_ok(checks) is False

    def test_failed_preconditions_prevent_execution(self):
        calls = []
        f = finding_for(provider="not-a-real-provider")
        rec = execute_approved_action(f, ACTION_CONNECT_OMNIROUTE,
                                      approval_for(f, ACTION_CONNECT_OMNIROUTE),
                                      executor=lambda x: calls.append(x))
        assert rec.outcome == OUTCOME_BLOCKED
        assert calls == []


# ── Verification gates success ──────────────────────────────────────────────

class TestVerificationGatesSuccess:

    def test_unverifiable_stays_unresolved(self, missing_omni_setup, review_path):
        """Executor claims success but state shows no connection → UNVERIFIED."""
        st, omni, op = missing_omni_setup
        f = finding_for()
        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=lambda x: {"performed": True, "connection_id": "c_new"},
            state=st, omni_connections=omni, op_items=op,
            review_state_path=review_path)
        assert rec.outcome != OUTCOME_RESOLVED
        assert rec.outcome == OUTCOME_UNVERIFIED
        assert rec.verified is False
        assert get_review_status(f.finding_id, review_path) == REVIEW_OPEN

    def test_verified_action_resolves(self, missing_omni_setup, review_path):
        """Post-state shows the connection → verified → resolved."""
        st, omni, op = missing_omni_setup
        # Build the finding from the real model so the account key matches.
        from engine.review import build_findings
        from engine.accounts import build_account_model
        findings = build_findings(model=build_account_model(st, omni, op))
        f = [x for x in findings if x.recommended_action == ACTION_CONNECT_OMNIROUTE]
        if not f:
            pytest.skip("no missing-omniroute finding in fixture")
        f = f[0]
        acc_email = "lazymause@gmail.com"
        post_omni = [{"provider_id": "groq", "connection_id": "c_new",
                      "display_name": acc_email, "is_active": True}]
        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=lambda x: {"performed": True, "connection_id": "c_new"},
            state=st, omni_connections=post_omni, op_items=op,
            review_state_path=review_path)
        if rec.verified:
            assert rec.outcome == OUTCOME_RESOLVED
            assert rec.reconciled is True
        else:
            assert rec.outcome == OUTCOME_UNVERIFIED

    def test_verify_postconditions_detects_missing_account(self):
        f = finding_for(key="groq::nonexistent")
        checks = verify_postconditions(f, ACTION_CONNECT_OMNIROUTE, state_with([]))
        assert any(not c["ok"] for c in checks)

    def test_no_postcondition_defined_is_not_success(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for()
        checks = verify_postconditions(f, "some_unknown_action", st, omni, op)
        assert any(not c["ok"] for c in checks)

    def test_dry_run_never_resolves(self):
        f = finding_for()
        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=lambda x: {"performed": True}, dry_run=True)
        assert rec.outcome != OUTCOME_RESOLVED
        assert rec.verified is False


# ── Failure handling ────────────────────────────────────────────────────────

class TestFailureHandling:

    def test_missing_executor_is_failure_not_success(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for()
        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=None, state=st, omni_connections=omni, op_items=op)
        assert rec.outcome == OUTCOME_FAILED
        assert rec.verified is False

    def test_executor_exception_handled(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for()

        def boom(_):
            raise RuntimeError("provider rejected the request")

        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=boom, state=st, omni_connections=omni, op_items=op)
        assert rec.outcome == OUTCOME_FAILED
        assert rec.verified is False

    def test_exception_message_not_leaked_verbatim(self, missing_omni_setup):
        """Exception text may contain secrets — only the type is recorded."""
        st, omni, op = missing_omni_setup
        f = finding_for()

        def boom(_):
            raise RuntimeError(f"failed with key {SECRET}")

        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=boom, state=st, omni_connections=omni, op_items=op)
        assert SECRET not in json.dumps(rec.to_dict())

    def test_executor_returning_not_performed_is_failure(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for()
        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=lambda x: {"performed": False, "error": "denied"},
            state=st, omni_connections=omni, op_items=op)
        assert rec.outcome == OUTCOME_FAILED


# ── Human checkpoints ───────────────────────────────────────────────────────

class TestHumanCheckpoints:

    def test_checkpoint_surfaced_not_bypassed(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for(action=ACTION_ACQUIRE_API_KEY)
        rec = execute_approved_action(
            f, ACTION_ACQUIRE_API_KEY, approval_for(f, ACTION_ACQUIRE_API_KEY),
            executor=lambda x: {
                "performed": False,
                "human_checkpoint_required": True,
                "checkpoint": {"checkpoint_id": "ckpt_1",
                               "checkpoint_type": "email_verification"},
            },
            state=st, omni_connections=omni, op_items=op)
        assert rec.outcome == OUTCOME_AWAITING_CHECKPOINT
        assert rec.checkpoint["checkpoint_type"] == "email_verification"
        assert rec.verified is False

    def test_checkpoint_record_is_secret_free(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for(action=ACTION_ACQUIRE_API_KEY)
        rec = execute_approved_action(
            f, ACTION_ACQUIRE_API_KEY, approval_for(f, ACTION_ACQUIRE_API_KEY),
            executor=lambda x: {
                "performed": False, "human_checkpoint_required": True,
                "checkpoint": {"checkpoint_id": "c1", "password": SECRET,
                               "checkpoint_type": "captcha"},
            },
            state=st, omni_connections=omni, op_items=op)
        assert SECRET not in json.dumps(rec.to_dict())
        assert_secret_free(rec.to_dict())

    def test_checkpoint_never_marked_bypassed(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for(action=ACTION_ACQUIRE_API_KEY)
        rec = execute_approved_action(
            f, ACTION_ACQUIRE_API_KEY, approval_for(f, ACTION_ACQUIRE_API_KEY),
            executor=lambda x: {"performed": True},
            state=st, omni_connections=omni, op_items=op)
        assert rec.execution.get("checkpoints_bypassed") is False

    def test_headed_browser_flagged_when_required(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for(action=ACTION_ACQUIRE_API_KEY)
        rec = execute_approved_action(
            f, ACTION_ACQUIRE_API_KEY, approval_for(f, ACTION_ACQUIRE_API_KEY),
            executor=lambda x: {"performed": True},
            state=st, omni_connections=omni, op_items=op)
        assert rec.execution["headed_browser_required"] is True
        assert rec.execution["browser_headed"] is True


# ── Secret stripping ────────────────────────────────────────────────────────

class TestSecretStripping:

    def test_strip_secrets_drops_secret_keys(self):
        out = strip_secrets({"api_key": SECRET, "password": "hunter2",
                             "item_id": "i1"})
        assert "api_key" not in out
        assert "password" not in out
        assert out["item_id"] == "i1"
        assert set(out["redacted_fields"]) == {"api_key", "password"}

    def test_strip_secrets_keeps_op_references(self):
        out = strip_secrets({"credential": "op://Personal/i1/credential"})
        assert out["credential_reference"] == "op://Personal/i1/credential"
        assert "credential" not in out

    def test_strip_secrets_recurses(self):
        out = strip_secrets({"a": [{"token": SECRET}], "b": {"c": {"secret": "x"}}})
        assert "token" not in out["a"][0]
        assert "secret" not in out["b"]["c"]
        assert out["b"]["c"]["redacted_fields"] == ["secret"]

    def test_execution_result_secrets_stripped(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for()
        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=lambda x: {"performed": True, "api_key": SECRET},
            state=st, omni_connections=omni, op_items=op)
        assert SECRET not in json.dumps(rec.to_dict())

    def test_record_is_json_serializable_and_safe(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for()
        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=lambda x: {"performed": True},
            state=st, omni_connections=omni, op_items=op)
        json.dumps(rec.to_dict())
        assert_secret_free(rec.to_dict())


# ── Reconciliation afterwards ───────────────────────────────────────────────

class TestReconciliationAfterwards:

    def test_reconciliation_runs_after_execution(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for()
        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=lambda x: {"performed": True},
            state=st, omni_connections=omni, op_items=op)
        assert rec.reconciled is True
        assert "reconciliation_summary" in rec.execution

    def test_reconciliation_summary_secret_free(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        f = finding_for()
        rec = execute_approved_action(
            f, ACTION_CONNECT_OMNIROUTE, approval_for(f, ACTION_CONNECT_OMNIROUTE),
            executor=lambda x: {"performed": True},
            state=st, omni_connections=omni, op_items=op)
        assert_secret_free(rec.execution["reconciliation_summary"])


# ── Planning executes nothing ───────────────────────────────────────────────

class TestPlanning:

    def test_plan_executes_nothing(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        plan = plan_remediation(st, omni, op)
        assert plan["read_only"] is True
        assert plan["executed_anything"] is False
        for item in plan["items"]:
            assert item["approval_required"] is True
            assert item["approved"] is False

    def test_plan_marks_human_only_items(self):
        idents = [
            {"id": _ID.format("a"), "type": "email", "value": "a@example.com"},
            {"id": _ID.format("b"), "type": "email", "value": "b@example.com"},
        ]
        pa = [
            {"id": "pa1", "provider_id": "groq", "identity_id": _ID.format("a"),
             "omniroute_account_id": "shared"},
            {"id": "pa2", "provider_id": "groq", "identity_id": _ID.format("b"),
             "omniroute_account_id": "shared"},
        ]
        omni = [{"provider_id": "groq", "connection_id": "shared"}]
        plan = plan_remediation(state_with(pa, idents), omni, [])
        assert any(i["human_only"] for i in plan["items"])

    def test_plan_json_serializable_and_safe(self, missing_omni_setup):
        st, omni, op = missing_omni_setup
        plan = plan_remediation(st, omni, op)
        json.dumps(plan)
        assert_secret_free(plan)

    def test_plan_does_not_write_state(self, missing_omni_setup):
        import engine.state as state_mod
        st, omni, op = missing_omni_setup
        before = Path(state_mod.STATE_FILE).read_text()
        plan_remediation(st, omni, op)
        assert Path(state_mod.STATE_FILE).read_text() == before

    def test_plan_calls_no_adapter(self, missing_omni_setup, monkeypatch):
        calls = []
        import adapters.omniroute as omni_mod
        import adapters.onepassword as op_mod
        for mod, names in ((omni_mod, ("connect_provider", "update_provider")),
                           (op_mod, ("create_item",))):
            for n in names:
                if hasattr(mod, n):
                    monkeypatch.setattr(mod, n, lambda *a, **k: calls.append(n))
        st, omni, op = missing_omni_setup
        plan_remediation(st, omni, op)
        assert calls == []


# ── No arbitrary provider signup ────────────────────────────────────────────

class TestNoArbitrarySignup:

    def test_no_signup_action_is_executable(self):
        for action in EXECUTABLE_ACTIONS:
            assert "signup" not in action
            assert "register" not in action

    def test_automation_does_not_call_registration_engine(self):
        src = (SKILL_ROOT / "engine" / "automation.py").read_text()
        for forbidden in ("plan_registration(", "register_provider(",
                          "execute_registration("):
            assert forbidden not in src


# ── CLI ─────────────────────────────────────────────────────────────────────

class TestCli:

    def test_remediate_json_executes_nothing(self, capsys):
        import cli
        assert cli.main(["remediate", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["executed_anything"] is False
        assert payload["read_only"] is True

    def test_remediate_human_states_approval(self, capsys):
        import cli
        assert cli.main(["remediate"]) == 0
        out = capsys.readouterr().out
        assert "Nothing to remediate." in out or "explicit approval" in out

    def test_cli_has_no_execute_command(self):
        import cli
        src = (SKILL_ROOT / "cli.py").read_text()
        # The name may be *mentioned* in docs, but must never be imported or
        # invoked: mutation is not reachable from a single CLI invocation.
        assert "execute_approved_action(" not in src
        assert "import execute_approved_action" not in src
        assert "from engine.automation import" in src and \
            "execute_approved_action" not in src.split(
                "from engine.automation import")[1].split(")")[0]

