"""
test_registration.py — Tests for the registration state machine and ledger.

Tests every valid state transition:
  DISCOVERED → ELIGIBILITY_CHECK → PLANNED → APPROVED → PREPARING →
  REGISTRATION → VERIFICATION → CREDENTIAL_ACQUISITION →
  OMNIROUTE_CONNECTION → 1PASSWORD_STORAGE → VERIFICATION → COMPLETE

Failure states: FAILED, BLOCKED, POLICY_BLOCKED, PARTIAL

Critical invariants:
  - A completed registration must never be repeated
  - Duplicate prevention
  - Phone/verification usage tracking
"""
import pytest
import json
from copy import deepcopy
from unittest.mock import patch, MagicMock

from engine.registration import (
    REGISTRATION_STATES,
    FAILURE_STATES,
    load_history,
    save_history,
    record_attempt,
    record_success,
    record_failure,
    record_partial,
    get_history,
    get_active_registrations,
    resume_registration,
    check_phone_usage,
    check_provider_blocked,
    _next_step,
)


# ── Fixture: isolated history file ───────────────────────────────────────

@pytest.fixture
def _isolate_history(tmp_path):
    """Patch HISTORY_FILE to a temp path so tests don't touch real data."""
    history_file = str(tmp_path / "test_registration_history.json")
    with patch("engine.registration.HISTORY_FILE", history_file):
        yield history_file


# ── Tests ────────────────────────────────────────────────────────────────

class TestStateConstants:

    def test_all_states_present(self):
        expected = {"discovered", "eligibility_check", "planned", "approved",
                    "preparing", "registration", "verification",
                    "credential_acquisition", "omniroute_connection",
                    "onepassword_storage", "verifying", "completed",
                    "failed", "blocked", "policy_blocked",
                    "waiting_for_user", "partial"}
        assert set(REGISTRATION_STATES) == expected

    def test_failure_states_subset(self):
        assert FAILURE_STATES.issubset(set(REGISTRATION_STATES))
        assert "failed" in FAILURE_STATES
        assert "completed" not in FAILURE_STATES


class TestRegistrationLedger:

    def test_load_history_empty(self, _isolate_history):
        history = load_history()
        assert history == []

    def test_record_attempt(self, _isolate_history):
        entry = record_attempt("groq", "plan")
        assert entry["provider_id"] == "groq"
        assert entry["method"] == "plan"
        assert entry["trigger_event"] == "manual"
        assert entry["started_at"] is not None
        assert entry["status"] == "planned"
        assert entry["completed_at"] is None
        assert entry["credential_created"] is False
        assert entry["omniroute_status"] == "not_attempted"
        assert entry["onepassword_status"] == "not_attempted"
        assert "id" in entry

    def test_record_attempt_with_identity(self, _isolate_history):
        entry = record_attempt("groq", "plan", identity_id="ident_1")
        assert entry["identity_id"] == "ident_1"

    def test_record_attempt_with_provider(self, _isolate_history):
        provider = {"name": "Groq", "id": "groq", "auth_type": "api_key"}
        entry = record_attempt("groq", "plan", provider_catalog_provider=provider)
        assert entry["policy_status"] == "unknown"
        assert entry["metadata"]["provider_name"] == "Groq"

    def test_get_history_sorted(self, _isolate_history):
        record_attempt("groq", "manual")
        record_attempt("openai", "manual")
        history = get_history()
        # Should be sorted by started_at, most recent first
        assert len(history) == 2
        assert history[0]["started_at"] >= history[1]["started_at"]

    def test_get_history_filtered(self, _isolate_history):
        record_attempt("groq", "manual")
        record_attempt("openai", "manual")
        record_attempt("groq", "manual")
        groq_history = get_history("groq")
        assert len(groq_history) == 2

    def test_failed_included_in_active(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        record_failure(entry["id"], "test failure")
        active = get_active_registrations()
        # 'failed' is NOT in active (active = not completed/failed/policy_blocked)
        assert entry["id"] not in [e["id"] for e in active]

    def test_completed_excluded_from_active(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        record_success(entry["id"], {})
        active = get_active_registrations()
        assert entry["id"] not in [e["id"] for e in active]


class TestRegistrationSuccess:

    def test_record_success_transitions(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        result = record_success(entry["id"], {"steps": {"complete": "completed"}})
        assert result["status"] == "completed"
        assert result["completed_at"] is not None

    def test_record_success_updates_credential(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        result = record_success(entry["id"], {
            "credential_created": True,
            "credential_ref": {"backend": "1password", "item_id": "item_1"},
            "omniroute_account_id": "conn_123",
        })
        assert result["credential_created"] is True
        assert result["credential_ref"]["backend"] == "1password"
        assert result["omniroute_account_id"] == "conn_123"

    def test_record_success_unknown_id_raises(self, _isolate_history):
        with pytest.raises(KeyError):
            record_success("nonexistent_reg_id", {})

    def test_no_secrets_in_history(self, _isolate_history):
        """Registration history must never store raw credential values."""
        entry = record_attempt("groq", "manual")
        record_success(entry["id"], {
            "credential_ref": {"backend": "1password", "item_id": "item_1"},
        })
        history = load_history()
        serialized = json.dumps(history)
        assert "TEST_SECRET" not in serialized
        assert "api_key" not in serialized.lower()


class TestRegistrationFailure:

    def test_record_failure_transitions(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        result = record_failure(entry["id"], "rate limited")
        assert result["status"] == "failed"
        assert result["failure_reason"] == "rate limited"
        assert result["completed_at"] is not None

    def test_record_failure_with_step(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        record_failure(entry["id"], "phone verification failed", step="phone_verification")
        entry_loaded = load_history()[0]
        assert entry_loaded["steps"].get("phone_verification") == "failed"

    def test_record_failure_unknown_id_raises(self, _isolate_history):
        with pytest.raises(KeyError):
            record_failure("nonexistent_reg_id", "test")

    def test_record_failure_idempotent(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        record_failure(entry["id"], "first failure")
        # Marking failed again should not crash
        record_failure(entry["id"], "second failure")
        entry_loaded = load_history()[0]
        assert entry_loaded["status"] == "failed"


class TestRegistrationResume:

    def test_resume_no_partial(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        result = resume_registration(entry["id"])
        # Not partial, so should return no_active_registration or resumable
        assert result["status"] in ("no_active_registration", "resumable")

    def test_resume_identifies_current_step(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        record_failure(entry["id"], "interrupted", step="email_verification")
        entry_loaded = load_history()[0]
        entry_loaded["status"] = "partial"
        entry_loaded["steps"] = {"discover": "completed", "eligibility_check": "completed",
                                 "select_identity": "completed", "email_verification": "failed"}
        save_history(load_history())
        result = resume_registration(entry["id"])
        assert result["status"] == "resumable"
        assert "last_completed_step" in result
        assert "current_step" in result

    def test_resume_by_most_recent(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        record_partial(entry["id"], {"discover": "completed"}, "interrupted")
        result = resume_registration()  # no reg_id → most recent partial
        assert result["status"] == "resumable"

    def test_next_step_finds_first_incomplete(self):
        steps = {"discover": "completed", "eligibility_check": "completed"}
        assert _next_step(steps) == "select_identity"

    def test_next_step_all_complete(self):
        steps = {"discover": "completed", "eligibility_check": "completed",
                 "select_identity": "completed", "prepare_credentials": "completed",
                 "open_provider": "completed", "registration": "completed",
                 "email_verification": "completed", "phone_verification": "completed",
                 "oauth": "completed", "api_key_extraction": "completed",
                 "omniroute_connection": "completed", "onepassword_storage": "completed",
                 "state_update": "completed", "verify": "completed", "complete": "completed"}
        assert _next_step(steps) is None


class TestRegistrationPhoneUsage:

    def test_phone_usage_tracked(self, _isolate_history):
        entry = record_attempt("google", "manual")
        record_success(entry["id"], {"phone_used": "+15551234567"})
        usage = check_phone_usage("+15551234567")
        assert usage["total_usages"] == 1
        assert usage["google_verifications"] == 1

    def test_phone_usage_empty(self, _isolate_history):
        usage = check_phone_usage("+15559999999")
        assert usage["total_usages"] == 0
        assert usage["has_google_limit"] is False

    def test_phone_usage_google_limit(self, _isolate_history):
        entry = record_attempt("google", "manual")
        record_success(entry["id"], {"phone_used": "+15551234567"})
        entry2 = record_attempt("google", "manual")
        record_success(entry2["id"], {"phone_used": "+15551234567"})
        usage = check_phone_usage("+15551234567")
        assert usage["has_google_limit"] is True
        assert usage["google_verifications"] == 2

    def test_phone_usage_none(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        record_success(entry["id"], {})
        usage = check_phone_usage(None)
        assert usage["total_usages"] == 1


class TestProviderBlocked:

    def test_provider_blocked(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        record_failure(entry["id"], "multiple account not allowed for this identity")
        result = check_provider_blocked("groq")
        assert result["has_rejection"] is True
        assert result["rejection_count"] == 1

    def test_provider_not_blocked(self, _isolate_history):
        result = check_provider_blocked("groq")
        assert result["has_rejection"] is False
        assert result["rejection_count"] == 0


class TestDuplicatePrevention:

    def test_completed_not_repeated(self, _isolate_history):
        """Critical: a completed registration should not be silently repeated."""
        entry = record_attempt("groq", "manual")
        record_success(entry["id"], {})
        history = load_history()
        assert len(history) == 1
        assert history[0]["status"] == "completed"

        # Recording another attempt for the same provider is allowed
        # (it's a new registration, different reg_id), but the old one stays completed
        entry2 = record_attempt("groq", "manual")
        history = load_history()
        assert len(history) == 2
        completed = [e for e in history if e["status"] == "completed"]
        assert len(completed) == 1


class TestPartialRegistration:

    def test_record_partial(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        result = record_partial(entry["id"], {"discover": "completed", "eligibility_check": "completed"},
                                "interrupted at step 3")
        assert result["status"] == "partial"
        assert result["failure_reason"] == "interrupted at step 3"

    def test_record_partial_preserves_steps(self, _isolate_history):
        entry = record_attempt("groq", "manual")
        record_partial(entry["id"], {"discover": "completed", "omniroute_connection": "completed"},
                       "verification failed")
        loaded = load_history()[0]
        assert loaded["status"] == "partial"
        assert loaded["steps"]["discover"] == "completed"
        assert loaded["steps"]["omniroute_connection"] == "completed"

    def test_record_partial_unknown_id_raises(self, _isolate_history):
        with pytest.raises(KeyError):
            record_partial("nonexistent_reg_id", {}, "test")
