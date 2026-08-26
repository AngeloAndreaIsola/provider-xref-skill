"""
test_phase7.py — Phase 7 tests: Operational UX, Orchestration & Automation Foundation.

Tests cover:
  1. recommendations() — prioritized, actionable opportunity list
  2. recommend_next() — highest-priority recommendation selector
  3. plan_recommended_batch() — batch execution request creation (no approval)
  4. get_batch_status() — read-only batch status query
  5. summarize_batch() — operational batch summary
  6. Phase 6 safety invariants preserved under Phase 7 operations

All Phase 7 operations are mutation-free:
  - recommendations() and recommend_next() are read-only
  - plan_recommended_batch() creates execution requests but NEVER approves or executes
  - get_batch_status() and summarize_batch() are read-only queries

No production state is modified — tests use isolated fixtures via conftest.py.
"""
import sys
import os
import json
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock

from engine.state import load_state, save_state, now_iso, default_state
from engine.executor import (
    create_execution_request,
    list_execution_requests,
    registration_status,
    get_batch_status,
    summarize_batch,
    EXECUTION_STATES,
)
from engine.planner import (
    find_opportunities,
    plan_recommended_batch,
)
from engine.audit import (
    recommendations,
    recommend_next,
    audit,
    _classify_priority,
    _next_action,
)
from engine import state as state_mod
from engine import utils as utils_mod
from engine import executor as exec_mod


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def mock_browser():
    """Mock the browser adapter to ensure it's never called in batch planning."""
    with patch("adapters.browser.api_key_flow") as mock:
        yield mock


@pytest.fixture
def mock_omniroute_post():
    """Mock OmniRoute POST to ensure it's never called without approval."""
    with patch("adapters.omniroute._api_request") as mock:
        yield mock


@pytest.fixture
def sample_recommendations(isolated_catalog):
    """Minimal recommendation dicts matching the recommendations() output shape."""
    return [
        {
            "provider": "agentrouter",
            "name": "AgentRouter",
            "auth_type": "api_key",
            "identity": "ident_email_1",
            "identity_label": "user@example.com",
            "score": 85,
            "confidence": 0.9,
            "policy_status": "allowed",
            "can_automate": True,
            "priority_tier": "high",
            "priority_label": "High priority — ready to register",
            "next_action": "plan_registration",
            "downstream_count": 3,
            "free_quota": "100K tokens",
            "signup_difficulty": "easy",
            "verification_requirements": ["email"],
            "omniroute_support": True,
        },
        {
            "provider": "anthropic",
            "name": "Anthropic",
            "auth_type": "api_key",
            "identity": "ident_email_1",
            "identity_label": "user@example.com",
            "score": 65,
            "confidence": 0.8,
            "policy_status": "unknown",
            "can_automate": False,
            "priority_tier": "high",
            "priority_label": "High priority — ready to register",
            "next_action": "review_and_approve",
            "downstream_count": 0,
            "free_quota": "$5 credit",
            "signup_difficulty": "moderate",
            "verification_requirements": ["email"],
            "omniroute_support": True,
        },
        {
            "provider": "claude",
            "name": "Anthropic Claude",
            "auth_type": "oauth",
            "identity": None,
            "identity_label": "any eligible",
            "score": 35,
            "confidence": 0.5,
            "policy_status": "allowed",
            "can_automate": True,
            "priority_tier": "medium",
            "priority_label": "Medium priority — review before registering",
            "next_action": "provide_identity",
            "downstream_count": 2,
            "free_quota": "$5 credit",
            "signup_difficulty": "moderate",
            "verification_requirements": ["email", "phone"],
            "omniroute_support": True,
        },
    ]


# ── recommendations() tests ──────────────────────────────────────────────────


class TestRecommendationsReadness:
    """Test that recommendations() is read-only and doesn't mutate state."""

    def test_recommendations_does_not_mutate_state(self, isolated_state, isolated_catalog):
        """recommendations() must not modify provider_state.json."""
        from engine.utils import load_json
        state_before = load_json(state_mod.STATE_FILE)
        recommendations()
        state_after = load_json(state_mod.STATE_FILE)
        assert json.dumps(state_before, sort_keys=True) == json.dumps(state_after, sort_keys=True)

    def test_recommendations_does_not_create_execution_requests(self, isolated_state, isolated_catalog):
        """recommendations() must not create execution request files."""
        from engine.executor import list_execution_requests
        before = len(list_execution_requests())
        recommendations()
        after = len(list_execution_requests())
        assert before == after

    def test_recommendations_does_not_call_omniroute_post(self, isolated_state, isolated_catalog, mock_omniroute_post):
        """recommendations() must not POST to OmniRoute."""
        recommendations()
        for call in mock_omniroute_post.call_args_list:
            method = call.kwargs.get("method") or (call.args[0] if call.args else None)
            assert method != "POST"

    def test_recommendations_does_not_call_browser(self, isolated_state, isolated_catalog, mock_browser):
        """recommendations() must not invoke browser automation."""
        recommendations()
        assert mock_browser.call_count == 0


class TestRecommendationsStructure:
    """Test the structure and content of recommendations() output."""

    def test_recommendations_returns_list(self, isolated_state, isolated_catalog):
        recs = recommendations()
        assert isinstance(recs, list)

    def test_recommendations_sorted_by_priority(self, isolated_state, isolated_catalog):
        """Recommendations should be sorted: high tier first, then by score."""
        recs = recommendations()
        if len(recs) < 2:
            pytest.skip("Need at least 2 opportunities for sort test")
        # Check priority ordering
        tier_order = {"high": 0, "medium": 1, "low": 2}
        for i in range(len(recs) - 1):
            cur_tier = tier_order.get(recs[i]["priority_tier"], 99)
            nxt_tier = tier_order.get(recs[i + 1]["priority_tier"], 99)
            assert cur_tier <= nxt_tier

    def test_recommendation_has_required_fields(self, isolated_state, isolated_catalog):
        recs = recommendations()
        if not recs:
            pytest.skip("No opportunities in default state")
        rec = recs[0]
        required = {"provider", "name", "auth_type", "score", "policy_status",
                    "priority_tier", "next_action", "priority_label"}
        assert required.issubset(rec.keys())

    def test_recommendation_score_in_range(self, isolated_state, isolated_catalog):
        recs = recommendations()
        for rec in recs:
            assert 0 <= rec["score"] <= 100
            assert 0.0 <= rec["confidence"] <= 1.0

    def test_recommendation_priority_tier_valid(self, isolated_state, isolated_catalog):
        recs = recommendations()
        valid_tiers = {"high", "medium", "low", "none"}
        for rec in recs:
            assert rec["priority_tier"] in valid_tiers

    def test_recommendation_next_action_valid(self, isolated_state, isolated_catalog):
        recs = recommendations()
        valid_actions = {"plan_registration", "review_policy", "provide_identity",
                         "review_and_approve", "do_not_register"}
        for rec in recs:
            assert rec["next_action"] in valid_actions

    def test_disallowed_providers_excluded(self, isolated_state, isolated_catalog):
        """Recommendations must never include disallowed providers."""
        recs = recommendations()
        from engine.audit import recommendations as recs_fn
        # Re-check against catalog to be sure
        recs = recommendations(isolated_state, isolated_catalog)
        for rec in recs:
            assert rec["policy_status"] != "disallowed"

    def test_all_recommendations_have_provider_names(self, isolated_state, isolated_catalog):
        recs = recommendations()
        for rec in recs:
            assert rec["name"]
            assert rec["provider"]


class TestPriorityClassification:
    """Test the _classify_priority helper."""

    def test_allowed_automatable_high_score(self):
        assert _classify_priority(75, "allowed", True) == "high"

    def test_allowed_automatable_medium_score(self):
        assert _classify_priority(50, "allowed", True) == "medium"

    def test_allowed_automatable_low_score(self):
        assert _classify_priority(20, "allowed", True) == "low"

    def test_unknown_policy_high_score(self):
        assert _classify_priority(80, "unknown", False) == "high"

    def test_unknown_policy_medium_score(self):
        assert _classify_priority(45, "unknown", False) == "medium"

    def test_unknown_policy_low_score(self):
        assert _classify_priority(10, "unknown", False) == "low"

    def test_disallowed_always_none(self):
        assert _classify_priority(99, "disallowed", False) == "none"
        assert _classify_priority(0, "disallowed", False) == "none"

    def test_requires_review(self):
        assert _classify_priority(75, "requires_review", False) == "high"
        assert _classify_priority(30, "requires_review", False) == "low"


class TestNextAction:
    """Test the _next_action helper."""

    def test_disallowed_do_not_register(self):
        opp = {"policy_status": "disallowed", "identity_blocker": False}
        assert _next_action(opp) == "do_not_register"

    def test_unknown_policy_review_policy(self):
        opp = {"policy_status": "unknown", "can_automate": False,
               "identity_blocker": False, "missing_identities": False}
        assert _next_action(opp) == "review_policy"

    def test_identity_blocker(self):
        opp = {"policy_status": "allowed", "can_automate": True,
               "identity_blocker": True}
        assert _next_action(opp) == "provide_identity"

    def test_missing_identities(self):
        opp = {"policy_status": "allowed", "can_automate": True,
               "identity_blocker": False, "missing_identities": ["email"]}
        assert _next_action(opp) == "provide_identity"

    def test_allowed_automatable_plan_registration(self):
        opp = {"policy_status": "allowed", "can_automate": True,
               "identity_blocker": False, "missing_identities": False}
        assert _next_action(opp) == "plan_registration"

    def test_requires_review_review_and_approve(self):
        opp = {"policy_status": "requires_review", "can_automate": False,
               "identity_blocker": False, "missing_identities": False}
        assert _next_action(opp) == "review_and_approve"

    def test_unknown_policy_with_auto_review_and_approve(self):
        opp = {"policy_status": "unknown", "can_automate": True,
               "identity_blocker": False, "missing_identities": False}
        assert _next_action(opp) == "review_and_approve"


class TestRecommendNext:
    """Test recommend_next() — the single "what should I do next?" entry point."""

    def test_returns_dict_or_none(self, isolated_state, isolated_catalog):
        result = recommend_next()
        assert result is None or isinstance(result, dict)

    def test_returns_highest_priority_first(self, isolated_state, isolated_catalog):
        """recommend_next should return the highest-tier, highest-score rec."""
        recs = recommendations()
        if not recs:
            assert recommend_next() is None
        else:
            next_rec = recommend_next()
            assert next_rec is not None
            assert next_rec["provider"] == recs[0]["provider"]

    def test_returns_none_when_no_opportunities(self, isolated_catalog):
        """When state has no identities, no opportunities exist."""
        empty_state = default_state()
        result = recommend_next(empty_state, isolated_catalog)
        assert result is None


# ── plan_recommended_batch() tests ────────────────────────────────────────────


class TestBatchPlanning:
    """Test plan_recommended_batch() — batch creation of execution requests."""

    def test_batch_creates_requests_for_recommendations(self, isolated_state, isolated_catalog,
                                                         sample_recommendations):
        """plan_recommended_batch creates one execution request per recommendation."""
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        assert batch["total_requested"] == 3
        assert batch["total_created"] == len(batch["created"])
        assert batch["total_created"] >= 1  # At least some should succeed

    def test_batch_requests_are_awaiting_approval(self, isolated_state, isolated_catalog,
                                                    sample_recommendations):
        """All batch-created requests must start in 'awaiting_approval'."""
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        for req in batch["created"]:
            assert req["status"] == "awaiting_approval"

    def test_batch_does_not_approve_or_execute(self, isolated_state, isolated_catalog,
                                                sample_recommendations):
        """Batch planning must NOT approve or execute any request."""
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        for req in batch["created"]:
            rid = req["request_id"]
            status = registration_status(rid)
            assert status["status"] == "awaiting_approval"
            assert status["approved"] is False
            assert status["workflow_result_status"] is None

    def test_batch_skips_already_connected(self, isolated_state, isolated_catalog):
        """Providers already connected in state are skipped."""
        # openai is connected in full_sample_state
        recs = [{
            "provider": "openai",
            "name": "OpenAI",
            "auth_type": "api_key",
            "identity": "ident_email_1",
            "identity_label": "user@example.com",
            "score": 100,
            "confidence": 1.0,
            "policy_status": "allowed",
            "can_automate": True,
            "priority_tier": "high",
            "priority_label": "High priority",
            "next_action": "plan_registration",
            "downstream_count": 0,
            "free_quota": "$5 credit",
            "signup_difficulty": "moderate",
            "verification_requirements": ["email"],
            "omniroute_support": True,
        }]
        batch = plan_recommended_batch(recs, state=isolated_state, catalog=isolated_catalog)
        assert batch["total_skipped"] == 1
        assert batch["skipped"][0]["provider"] == "openai"
        assert batch["skipped"][0]["reason"] == "already_connected"

    def test_batch_has_batch_id(self, isolated_state, isolated_catalog, sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        assert batch["batch_id"] is not None
        assert len(batch["batch_id"]) > 0

    def test_batch_has_created_at(self, isolated_state, isolated_catalog, sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        assert batch["created_at"] is not None

    def test_batch_status_is_planned(self, isolated_state, isolated_catalog, sample_recommendations):
        """Batch status should be 'planned' — not approved or executed."""
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        assert batch["status"] == "planned"

    def test_batch_records_created_and_skipped(self, isolated_state, isolated_catalog,
                                                sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        assert len(batch["created"]) == len(batch["created"])  # tautology check
        assert batch["total_requested"] == batch["total_created"] + batch["total_skipped"] + batch["total_errors"]

    def test_batch_idempotency_creates_duplicates(self, isolated_state, isolated_catalog,
                                                   sample_recommendations):
        """Calling plan_recommended_batch twice with the same recommendations creates
        new execution requests each time.

        This is intentional: plan_recommended_batch operates on a provided
        recommendation list, not on state-discovered opportunities. Deduplication
        at the provider level is handled by find_opportunities() which skips
        already-connected providers. If the same provider appears in two
        separate batches, that is the user's choice and each is tracked
        separately. The key safety property is that neither call approves
        or executes.
        """
        batch1 = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        batch2 = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        # Both should create requests (no dedup at the planning level)
        if batch1["total_created"] > 0:
            assert batch2["total_created"] == batch1["total_created"]
            # Status of all created requests is still awaiting_approval
            for req in batch2["created"]:
                status = registration_status(req["request_id"])
                assert status["status"] == "awaiting_approval"
                assert status["approved"] is False

    def test_batch_no_secrets_in_created_requests(self, isolated_state, isolated_catalog,
                                                    sample_recommendations):
        """Execution request files must never contain secrets."""
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        for req in batch["created"]:
            from engine.executor import _load_request
            loaded = _load_request(req["request_id"])
            serialized = json.dumps(loaded)
            assert "sk-" not in serialized
            assert "TEST_SECRET" not in serialized
            # credential_ref may exist but must not contain raw values
            cred = loaded.get("plan", {}).get("credential_ref")
            if cred:
                assert "value" not in cred
                assert "api_key" not in str(cred).lower() or "api_key" not in cred


class TestBatchPlanningSafety:
    """Phase 6 safety invariants must hold under batch planning."""

    def test_batch_deny_providers_blocked(self, isolated_state, isolated_catalog):
        """DENY providers in the batch should have their requests in awaiting_approval
        but would be blocked by preflight (not auto-approved)."""
        # cursor is a DENY provider in the catalog
        recs = [{
            "provider": "cursor",
            "name": "Cursor",
            "auth_type": "oauth",
            "identity": "ident_email_1",
            "identity_label": "user@example.com",
            "score": 90,
            "confidence": 0.9,
            "policy_status": "disallowed",
            "can_automate": False,
            "priority_tier": "none",
            "priority_label": "Not recommended",
            "next_action": "do_not_register",
            "downstream_count": 0,
            "free_quota": "Unknown",
            "signup_difficulty": "unknown",
            "verification_requirements": [],
            "omniroute_support": False,
        }]
        batch = plan_recommended_batch(recs, state=isolated_state, catalog=isolated_catalog)
        # Request is created (awaiting_approval) but preflight would block
        for req in batch["created"]:
            status = registration_status(req["request_id"])
            assert status["status"] == "awaiting_approval"
            # Preflight would block — verify
            from engine.executor import preflight
            pf = preflight(req["request_id"])
            assert pf["allowed"] is False

    def test_batch_unknown_never_auto_approved(self, isolated_state, isolated_catalog):
        """UNKNOWN policy requests in the batch must remain awaiting_approval."""
        recs = [{
            "provider": "deepseek",
            "name": "DeepSeek",
            "auth_type": "api_key",
            "identity": "ident_email_1",
            "identity_label": "user@example.com",
            "score": 90,
            "confidence": 0.9,
            "policy_status": "unknown",
            "can_automate": False,
            "priority_tier": "high",
            "priority_label": "High priority",
            "next_action": "review_and_approve",
            "downstream_count": 0,
            "free_quota": "Unknown",
            "signup_difficulty": "unknown",
            "verification_requirements": [],
            "omniroute_support": True,
        }]
        batch = plan_recommended_batch(recs, state=isolated_state, catalog=isolated_catalog)
        for req in batch["created"]:
            status = registration_status(req["request_id"])
            assert status["status"] == "awaiting_approval"
            assert status["approved"] is False
            assert status["policy_status"] == "unknown"


# ── get_batch_status() tests ───────────────────────────────────────────────


class TestBatchStatus:
    """Test get_batch_status() — read-only batch status query."""

    def test_batch_status_returns_list(self, isolated_state, isolated_catalog, sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        statuses = get_batch_status(request_ids)
        assert isinstance(statuses, list)
        assert len(statuses) == len(request_ids)

    def test_batch_status_each_has_fields(self, isolated_state, isolated_catalog, sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        for s in get_batch_status(request_ids):
            assert "request_id" in s
            assert "status" in s
            assert "provider_id" in s

    def test_batch_status_not_found(self):
        """Querying non-existent request IDs returns not_found status."""
        statuses = get_batch_status(["nonexistent_exec_1", "nonexistent_exec_2"])
        for s in statuses:
            assert s["status"] == "not_found"

    def test_batch_status_is_read_only(self, isolated_state, isolated_catalog, sample_recommendations):
        """get_batch_status must not modify any request files."""
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        # Capture request data before
        from engine.executor import _load_request
        before = {rid: _load_request(rid) for rid in request_ids}
        # Query status
        get_batch_status(request_ids)
        # Verify unchanged
        after = {rid: _load_request(rid) for rid in request_ids}
        for rid in request_ids:
            assert json.dumps(before[rid], sort_keys=True) == json.dumps(after[rid], sort_keys=True)


# ── summarize_batch() tests ───────────────────────────────────────────────


class TestSummarizeBatch:
    """Test summarize_batch() — operational batch summary."""

    def test_summarize_returns_dict(self, isolated_state, isolated_catalog, sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        if not request_ids:
            pytest.skip("No requests were created")
        summary = summarize_batch(request_ids)
        assert isinstance(summary, dict)
        assert summary["total"] == len(request_ids)

    def test_summarize_has_by_status(self, isolated_state, isolated_catalog, sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        if not request_ids:
            pytest.skip("No requests were created")
        summary = summarize_batch(request_ids)
        assert "by_status" in summary
        assert isinstance(summary["by_status"], dict)
        # All created requests start in awaiting_approval
        assert summary["by_status"].get("awaiting_approval") == len(request_ids)

    def test_summarize_has_by_provider(self, isolated_state, isolated_catalog, sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        if not request_ids:
            pytest.skip("No requests were created")
        summary = summarize_batch(request_ids)
        assert "by_provider" in summary
        assert isinstance(summary["by_provider"], dict)

    def test_summarize_has_batch_id(self, isolated_state, isolated_catalog, sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        if not request_ids:
            pytest.skip("No requests were created")
        summary = summarize_batch(request_ids)
        assert "batch_id" in summary
        assert len(summary["batch_id"]) == 16  # sha256[:16]

    def test_summarize_has_awaiting_approval_list(self, isolated_state, isolated_catalog,
                                                    sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        if not request_ids:
            pytest.skip("No requests were created")
        summary = summarize_batch(request_ids)
        assert "awaiting_approval" in summary
        assert isinstance(summary["awaiting_approval"], list)

    def test_summarize_has_completed_list(self, isolated_state, isolated_catalog, sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        if not request_ids:
            pytest.skip("No requests were created")
        summary = summarize_batch(request_ids)
        assert "completed" in summary
        assert isinstance(summary["completed"], list)

    def test_summarize_has_blocked_list(self, isolated_state, isolated_catalog,
                                         sample_recommendations):
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        if not request_ids:
            pytest.skip("No requests were created")
        summary = summarize_batch(request_ids)
        assert "blocked" in summary
        assert "partial" in summary
        assert "failed" in summary
        assert "cancelled" in summary
        assert "ready_to_execute" in summary

    def test_summarize_counters_add_up(self, isolated_state, isolated_catalog, sample_recommendations):
        """total should equal the sum of all individual lists plus uncategorized."""
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        if not request_ids:
            pytest.skip("No requests were created")
        summary = summarize_batch(request_ids)
        counted = (len(summary["awaiting_approval"]) +
                   len(summary["ready_to_execute"]) +
                   len(summary["blocked"]) +
                   len(summary["completed"]) +
                   len(summary["partial"]) +
                   len(summary["failed"]) +
                   len(summary["cancelled"]) +
                   len(summary["not_found"]))
        # by_status total should also equal total
        status_count = sum(summary["by_status"].values())
        assert status_count == summary["total"]
        # All requests are in categorized buckets (awaiting_approval in test context)
        assert counted == summary["total"]

    def test_summarize_is_read_only(self, isolated_state, isolated_catalog, sample_recommendations):
        """summarize_batch must not modify any request files."""
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        if not request_ids:
            pytest.skip("No requests were created")
        from engine.executor import _load_request
        before = {rid: _load_request(rid) for rid in request_ids}
        summarize_batch(request_ids)
        after = {rid: _load_request(rid) for rid in request_ids}
        for rid in request_ids:
            assert json.dumps(before[rid], sort_keys=True) == json.dumps(after[rid], sort_keys=True)


# ── Integration: batch → status → summarize ─────────────────────────────────


class TestBatchOperationalFlow:
    """Test the full operational flow: recommendations → batch → status → summary."""

    def test_full_flow_read_only(self, isolated_state, isolated_catalog):
        """The full Phase 7 flow must be safe to run on isolation state."""
        # 1. Get recommendations
        recs = recommendations(isolated_state, isolated_catalog)
        # 2. Plan batch (creates execution requests, no approval)
        batch = plan_recommended_batch(recs, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        # 3. Query batch status
        statuses = get_batch_status(request_ids)
        # 4. Summarize batch
        summary = summarize_batch(request_ids)

        assert summary["total"] == len(request_ids)
        assert len(statuses) == len(request_ids)
        for s in statuses:
            assert s["status"] == "awaiting_approval"

    def test_full_flow_no_secrets(self, isolated_state, isolated_catalog, sample_recommendations):
        """Full flow must never expose secrets."""
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        summary = summarize_batch(request_ids)
        serialized = json.dumps(summary, default=str)
        assert "sk-" not in serialized
        assert "TEST_SECRET" not in serialized

    def test_full_flow_no_execution(self, isolated_state, isolated_catalog, sample_recommendations):
        """Full flow must never execute — only create awaiting_approval requests."""
        batch = plan_recommended_batch(sample_recommendations, state=isolated_state, catalog=isolated_catalog)
        request_ids = [r["request_id"] for r in batch["created"]]
        statuses = get_batch_status(request_ids)
        for s in statuses:
            assert s["status"] == "awaiting_approval"
            assert s["workflow_result_status"] is None
