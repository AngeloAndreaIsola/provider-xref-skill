"""
test_planner.py — Tests for the opportunity planner.

Tests:
  - make_opportunity()
  - find_opportunities()
  - plan_new_phone()
  - plan_new_email()
  - plan_registration()
  - _find_compatible_identities()

Verifies:
  - already-used opportunities are excluded
  - prohibited opportunities are excluded
  - unknown opportunities are not silently approved
  - requirements are respected
  - scores are deterministic and bounded 0–100
"""
import pytest
import json
from unittest.mock import patch

from engine.planner import (
    make_opportunity, find_opportunities, plan_new_phone, plan_new_email,
    plan_registration, _find_compatible_identities, _get_skill_path,
)
from engine.catalog import load_catalog, get_provider, get_all_providers, default_catalog
from engine.state import default_state
from engine.graph import ProviderGraph
from engine.audit import _score_opportunity


class TestMakeOpportunity:

    def test_opportunity_has_required_fields(self, isolated_catalog, full_sample_state):
        state = dict(full_sample_state)
        with patch("engine.planner.load_state", return_value=state):
            provider = get_provider(isolated_catalog, "openai")
            identity = {
                "id": "ident_1", "type": "email", "value": "test@example.com",
                "status": "available", "created_at": "2025-01-01T00:00:00Z",
                "last_seen": "2025-01-01T00:00:00Z", "label": "Test",
            }
            opp = make_opportunity(provider, identity, isolated_catalog)

        assert opp["provider"] == "openai"
        assert opp["name"] == "OpenAI"
        assert opp["auth_type"] == "api_key"
        assert opp["identity"] == "ident_1"
        assert "value" in opp
        assert "confidence" in opp
        assert "policy_status" in opp
        assert "requirements" in opp
        assert "free_quota" in opp
        assert "omniroute_support" in opp
        assert "downstream_count" in opp

    def test_opportunity_without_identity(self, isolated_catalog):
        with patch("engine.planner.load_state", return_value=default_state()):
            provider = get_provider(isolated_catalog, "openai")
            opp = make_opportunity(provider, None, isolated_catalog)
        assert opp["identity"] is None
        assert opp["identity_label"] == "any eligible"

    def test_opportunity_score_in_range(self, isolated_catalog):
        with patch("engine.planner.load_state", return_value=default_state()):
            provider = get_provider(isolated_catalog, "openai")
            identity = {
                "id": "ident_1", "type": "email", "value": "test@example.com",
                "status": "available",
            }
            opp = make_opportunity(provider, identity, isolated_catalog)
        assert 0 <= opp["value"] <= 100
        assert 0.0 <= opp["confidence"] <= 1.0


class TestFindOpportunities:

    def test_find_opportunities_with_email_identity(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Test"},
        ]
        opps = find_opportunities(state, isolated_catalog)
        assert len(opps) > 0
        provider_ids = [o["provider"] for o in opps]
        assert "groq" in provider_ids or "openai" in provider_ids

    def test_find_opportunities_excludes_connected(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "active", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Test"},
        ]
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": "ident_1",
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        opps = find_opportunities(state, isolated_catalog)
        provider_ids = [o["provider"] for o in opps]
        assert "groq" not in provider_ids

    def test_find_opportunities_excludes_disallowed(self, isolated_catalog):
        """The forbidden_provider has disallowed policy — must be excluded."""
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "phone", "value": "+15551234567",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Test"},
        ]
        opps = find_opportunities(state, isolated_catalog)
        provider_ids = [o["provider"] for o in opps]
        assert "forbidden_provider" not in provider_ids

    def test_find_opportunities_sorted_by_score(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Test"},
        ]
        opps = find_opportunities(state, isolated_catalog)
        scores = [o["value"] for o in opps]
        assert scores == sorted(scores, reverse=True)

    def test_find_opportunities_no_identities(self, isolated_catalog):
        state = default_state()
        opps = find_opportunities(state, isolated_catalog)
        assert opps == []

    def test_find_opportunities_excludes_unknown_from_auto_approve(self, isolated_catalog):
        """Unknown policy providers should not be auto-approved."""
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Test"},
        ]
        opps = find_opportunities(state, isolated_catalog)
        for opp in opps:
            assert opp["policy_status"] in ("allowed", "unknown", "restricted")
            if opp["policy_status"] == "unknown":
                assert opp["can_automate"] is False


class TestPlanNewPhone:

    def test_plan_new_phone_returns_plan(self, isolated_catalog, tmp_path):
        """plan_new_phone should return a valid plan dict."""
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_new_phone("+15551234567", default_state(), isolated_catalog)
        assert plan is not None
        assert "id" in plan
        assert "trigger_event" in plan
        assert plan["trigger_event"] == "new_phone"
        assert "phone_number" in plan
        assert plan["phone_number"] == "+15551234567"
        assert "ranked_plan" in plan
        assert "graph" in plan

    def test_plan_new_phone_graph_has_nodes(self, isolated_catalog, tmp_path):
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_new_phone("+15551234567", default_state(), isolated_catalog)
        assert "nodes" in plan["graph"]
        assert isinstance(plan["graph"]["nodes"], list)

    def test_plan_new_phone_excludes_disallowed(self, isolated_catalog, tmp_path):
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_new_phone("+15551234567", default_state(), isolated_catalog)
        for node in plan["graph"]["nodes"]:
            if "provider_id" in node:
                assert node["provider_id"] != "forbidden_provider"

    def test_plan_new_phone_already_exists(self, isolated_catalog, tmp_path):
        state = default_state()
        state["identities"] = [
            {"id": "ident_phone_1", "type": "phone", "value": "+15551234567",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Phone"},
        ]
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_new_phone("+15551234567", state, isolated_catalog)
        assert plan["phone_number"] == "+15551234567"

    def test_plan_new_phone_score_range(self, isolated_catalog, tmp_path):
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_new_phone("+15551234567", default_state(), isolated_catalog)
        for node in plan["graph"]["nodes"]:
            if "score" in node:
                assert 0 <= node["score"] <= 100

    def test_plan_new_phone_summary(self, isolated_catalog, tmp_path):
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_new_phone("+15551234567", default_state(), isolated_catalog)
        s = plan["summary"]
        assert "identity_opportunities" in s
        assert "direct_provider_opportunities" in s
        assert "downstream_provider_opportunities" in s


class TestPlanNewEmail:

    def test_plan_new_email_returns_plan(self, isolated_catalog, tmp_path):
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_new_email("new@test.com", default_state(), isolated_catalog)
        assert plan is not None
        assert "id" in plan
        assert "trigger_event" in plan
        assert plan["trigger_event"] == "new_email"
        assert "email_address" in plan
        assert plan["email_address"] == "new@test.com"
        assert "ranked_plan" in plan
        assert "graph" in plan

    def test_plan_new_email_graph_has_email_node(self, isolated_catalog, tmp_path):
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_new_email("new@test.com", default_state(), isolated_catalog)
        nodes = plan["graph"]["nodes"]
        assert any("new@test.com" in str(n.get("label", "")) for n in nodes)

    def test_plan_new_email_already_exists(self, isolated_catalog, tmp_path):
        state = default_state()
        state["identities"] = [
            {"id": "ident_email_1", "type": "email", "value": "new@test.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Email"},
        ]
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_new_email("new@test.com", state, isolated_catalog)
        assert plan["email_address"] == "new@test.com"

    def test_plan_new_email_score_range(self, isolated_catalog, tmp_path):
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_new_email("new@test.com", default_state(), isolated_catalog)
        for node in plan["graph"]["nodes"]:
            if "score" in node:
                assert 0 <= node["score"] <= 100


class TestPlanRegistration:

    def test_plan_registration_success(self, isolated_catalog, tmp_path):
        """Plan registration for an eligible provider."""
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Test"},
        ]
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_registration("groq", state, isolated_catalog)
        assert plan is not None
        assert "provider_id" in plan
        assert plan["provider_id"] == "groq"
        assert "steps" in plan
        assert "workflow" in plan

    def test_plan_registration_already_connected(self, isolated_catalog, tmp_path):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "active"},
        ]
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": "ident_1",
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_registration("groq", state, isolated_catalog)
        assert plan["status"] == "completed"

    def test_plan_registration_missing_provider(self, isolated_catalog, tmp_path):
        state = default_state()
        with patch("engine.planner._get_skill_path", return_value=str(tmp_path / "plans")):
            with patch("engine.utils.save_json_atomic"):
                plan = plan_registration("nonexistent", state, isolated_catalog)
        assert plan["status"] == "failed"
        assert "not found" in plan["error"].lower()


class TestOpportunityScoring:

    def test_score_deterministic(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Test"},
        ]
        with patch("engine.planner.load_state", return_value=dict(state)):
            opps1 = find_opportunities(state, isolated_catalog)
            opps2 = find_opportunities(state, isolated_catalog)
        ids1 = sorted(o["provider"] for o in opps1)
        ids2 = sorted(o["provider"] for o in opps2)
        assert ids1 == ids2
        scores1 = {o["provider"]: o["value"] for o in opps1}
        scores2 = {o["provider"]: o["value"] for o in opps2}
        for pid in scores1:
            assert scores1[pid] == scores2[pid]

    def test_scores_in_range(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Test"},
        ]
        opps = find_opportunities(state, isolated_catalog)
        for opp in opps:
            assert 0 <= opp["value"] <= 100


class TestFindCompatibleIdentities:

    def test_email_identity_matches_email_requirement(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Test"},
        ]
        graph = ProviderGraph(state, isolated_catalog)
        provider = get_provider(isolated_catalog, "openai")
        result = _find_compatible_identities(graph, provider)
        assert len(result) == 1
        assert result[0]["type"] == "email"

    def test_no_compatible_identity(self, isolated_catalog):
        """Phone-only provider with no phone identity."""
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available"},
        ]
        graph = ProviderGraph(state, isolated_catalog)
        provider = get_provider(isolated_catalog, "forbidden_provider")
        result = _find_compatible_identities(graph, provider)
        assert len(result) == 0
