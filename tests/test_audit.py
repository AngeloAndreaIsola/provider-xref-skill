"""
test_audit.py — Tests for the audit module.

Tests:
  - identity grouping
  - health scoring
  - unused identities
  - connected providers
  - missing/unconnected providers
  - high-value opportunities
  - Markdown output (audit_text)

The audit() function loads state and catalog internally via
engine.state.load_state and engine.catalog.load_catalog, so tests
patch those module-level references.
"""
import pytest
import json
from unittest.mock import patch

from engine.audit import audit, audit_text, _has_compatible_identity, _can_automate, _score_opportunity
from engine.catalog import get_all_providers
from engine.state import default_state


class TestAuditStructure:

    def test_audit_returns_dict(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        assert isinstance(result, dict)

    def test_audit_has_summary(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        assert "summary" in result
        s = result["summary"]
        assert "identities" in s
        assert "external_accounts" in s
        assert "provider_accounts" in s
        assert "connected_providers" in s
        assert "partially_configured" in s
        assert "known_but_unused_providers" in s
        assert "unknown_providers" in s
        assert "available_opportunities" in s


class TestAuditIdentityGrouping:

    def test_identities_by_type(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        assert "identities" in result
        assert "by_type" in result["identities"]
        by_type = result["identities"]["by_type"]
        assert "phone" in by_type or "email" in by_type or "google" in by_type

    def test_identities_total_matches(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        assert result["identities"]["total"] == result["summary"]["identities"]


class TestAuditProviderAccounts:

    def test_provider_account_status_breakdown(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        pa = result["provider_accounts"]
        assert "connected" in pa
        assert "partially_configured" in pa
        assert "disconnected" in pa
        assert "error" in pa
        assert "total" in pa

    def test_connected_plus_disconnected_le_total(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        pa = result["provider_accounts"]
        assert pa["connected"] + pa["disconnected"] <= pa["total"]


class TestAuditUnusedIdentities:

    def test_unused_identities_listed(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        assert "unused_identities" in result
        assert isinstance(result["unused_identities"], list)

    def test_unused_identities_have_ids(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        for unused in result["unused_identities"]:
            assert "id" in unused
            assert "type" in unused


class TestAuditOpportunities:

    def test_high_value_opportunities_sorted(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        opps = result["high_value_opportunities"]
        scores = [o["score"] for o in opps]
        assert scores == sorted(scores, reverse=True)

    def test_high_value_opportunities_score_above_threshold(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        for opp in result["high_value_opportunities"]:
            assert opp["score"] > 30

    def test_high_value_excludes_disallowed(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        for opp in result["high_value_opportunities"]:
            assert opp["policy_status"] != "disallowed"


class TestAuditBlockedAndUnknown:

    def test_blocked_opportunities(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        assert "blocked_opportunities" in result
        assert isinstance(result["blocked_opportunities"], list)

    def test_policy_unknown_listed(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        assert "policy_unknown" in result
        assert isinstance(result["policy_unknown"], list)


class TestAuditBottlenecks:

    def test_verification_bottlenecks(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        assert "identity_bottlenecks" in result
        assert isinstance(result["identity_bottlenecks"], list)


class TestAuditDuplicates:

    def test_duplicate_opportunities(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        assert "duplicate_opportunities_count" in result
        assert "duplicate_opportunities" in result
        assert result["duplicate_opportunities_count"] == len(result["duplicate_opportunities"])


class TestAuditMarkdownOutput:

    def test_audit_text_returns_string(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            text = audit_text()
        assert isinstance(text, str)
        assert len(text) > 0

    def test_audit_text_has_header(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            text = audit_text()
        assert "Audit" in text or "Provider" in text

    def test_audit_text_mentions_identities(self, isolated_state, isolated_catalog):
        with patch("engine.audit.load_state", return_value=isolated_state), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            text = audit_text()
        assert "Identit" in text


class TestAuditHelpers:

    def test_has_compatible_identity_no_identity(self, isolated_catalog):
        from engine.graph import ProviderGraph
        state = default_state()
        graph = ProviderGraph(state, isolated_catalog)
        provider = {"identity_requirements": ["email"], "identity_relationships": []}
        result = _has_compatible_identity(graph, provider)
        assert result is False

    def test_has_compatible_identity_with_email(self, isolated_catalog):
        from engine.graph import ProviderGraph
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available", "verification": {"email_verified": True}},
        ]
        graph = ProviderGraph(state, isolated_catalog)
        provider = {"identity_requirements": ["email"], "identity_relationships": []}
        result = _has_compatible_identity(graph, provider)
        assert result is True

    def test_can_automate_true(self, isolated_catalog):
        from engine.catalog import get_provider
        cat = isolated_catalog
        # The fixture catalog has openai with automation_allowed "allowed"
        for p_id in ["openai"]:
            p = get_provider(cat, p_id)
            if p:
                ok = _can_automate(cat, p_id)
                assert ok is True
                break
        else:
            # If no allowed provider in fixture, test against real catalog
            from engine.catalog import load_catalog
            cat = load_catalog()
            for p in get_all_providers(cat):
                if p.get("policy", {}).get("automation_allowed") == "allowed":
                    ok = _can_automate(cat, p["id"])
                    assert ok is True
                    break

    def test_can_automate_false_for_unknown(self, isolated_catalog):
        from engine.catalog import get_provider
        cat = isolated_catalog
        # The fixture catalog has groq with automation_allowed "unknown"
        for p_id in ["groq"]:
            p = get_provider(cat, p_id)
            if p:
                assert _can_automate(cat, p_id) is False
                break
        else:
            from engine.catalog import load_catalog
            cat = load_catalog()
            for p in get_all_providers(cat):
                if p.get("policy", {}).get("automation_allowed") == "unknown":
                    assert _can_automate(cat, p["id"]) is False
                    break


class TestAuditEmptyState:

    def test_audit_with_empty_state(self, isolated_catalog):
        from engine.state import default_state
        with patch("engine.audit.load_state", return_value=default_state()), \
             patch("engine.audit.load_catalog", return_value=isolated_catalog):
            result = audit()
        assert result["summary"]["identities"] == 0
        assert result["summary"]["provider_accounts"] == 0
        assert result["identities"]["total"] == 0
