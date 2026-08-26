"""
test_policy.py — Tests for the policy engine.

Tests every PolicyResult equivalent (allowed/disallowed/unknown/restricted):

CRITICAL INVARIANT:
  UNKNOWN must NEVER implicitly become ALLOW.

Tests:
  - can_create=true → allowed
  - can_create=false → disallowed
  - missing can_create → unknown
  - missing provider → unknown
  - prohibited provider
  - provider requiring review
"""
import pytest

from engine.policy import (
    get_policy, _default_policy, can_automate_registration,
    can_create_multiple_accounts, can_use_third_party_proxy,
    can_reuse_phone, get_opportunity_policy_status, policy_summary,
    policy_risk_score,
)
from engine.catalog import load_catalog, get_provider


class TestPolicyDefaults:
    """Tests for default policy behavior."""

    def test_default_policy_returns_all_unknown(self):
        policy = _default_policy()
        assert policy["automation_allowed"] == "unknown"
        assert policy["multiple_accounts"] == "unknown"
        assert policy["third_party_proxy_allowed"] == "unknown"
        assert policy["phone_reuse_allowed"] == "unknown"
        assert policy["duplicate_account_policy"] == "unknown"

    def test_get_policy_for_missing_provider(self):
        """Unknown provider should return default policy (all unknown)."""
        cat = load_catalog()
        policy = get_policy(cat, "nonexistent_provider")
        assert policy["automation_allowed"] == "unknown"

    def test_get_policy_for_existing_provider(self):
        """Existing provider should have its policy filled in."""
        cat = load_catalog()
        policy = get_policy(cat, "groq")
        assert policy["automation_allowed"] in ("allowed", "disallowed", "restricted", "unknown")


class TestCanAutomateRegistration:
    """Tests for can_automate_registration().

    CRITICAL: UNKNOWN must NEVER become ALLOW.
    """

    def test_allowed_provider_can_automate(self):
        """Provider with automation_allowed='allowed' → can_automate=True."""
        cat = load_catalog()
        # Find a provider with 'allowed' policy
        for p_id in ["claude", "cursor", "kiro", "kilocode", "antigravity"]:
            p = get_provider(cat, p_id)
            if p and p.get("policy", {}).get("automation_allowed") == "allowed":
                can_auto, reason = can_automate_registration(cat, p_id)
                assert can_auto is True
                assert "allowed" in reason.lower()
                break

    def test_disallowed_provider_cannot_automate(self):
        """Provider with automation_allowed='disallowed' → can_automate=False."""
        cat = load_catalog()
        # Google, GitHub, Microsoft, Codex, Cursor all disallow
        for p_id in ["google", "github", "microsoft", "codex"]:
            p = get_provider(cat, p_id)
            if p and p.get("policy", {}).get("automation_allowed") == "disallowed":
                can_auto, reason = can_automate_registration(cat, p_id)
                assert can_auto is False
                assert "disallow" in reason.lower()
                break

    def test_unknown_provider_does_not_automate(self):
        """Provider with automation_allowed='unknown' → can_automate=False.

        CRITICAL INVARIANT: UNKNOWN MUST NEVER BECOME ALLOW.
        """
        cat = load_catalog()
        # Groq, DeepSeek, Anthropic etc. have unknown policy
        for p_id in ["groq", "deepseek", "anthropic"]:
            p = get_provider(cat, p_id)
            if p and p.get("policy", {}).get("automation_allowed") == "unknown":
                can_auto, reason = can_automate_registration(cat, p_id)
                assert can_auto is False
                assert "unknown" in reason.lower() or "manual" in reason.lower()
                break

    def test_restricted_provider_does_not_automate(self):
        """Provider with automation_allowed='restricted' → can_automate=False."""
        cat = load_catalog()
        # Look for restricted
        for p in cat.get("providers", []):
            if p.get("policy", {}).get("automation_allowed") == "restricted":
                can_auto, reason = can_automate_registration(cat, p["id"])
                assert can_auto is False
                assert "restricted" in reason.lower() or "manual" in reason.lower()
                break

    def test_missing_provider_returns_false(self):
        """Provider not in catalog → can_automate=False, reason mentions unknown."""
        cat = load_catalog()
        can_auto, reason = can_automate_registration(cat, "nonexistent")
        assert can_auto is False
        assert "unknown" in reason.lower() or "unknown" in reason.lower()


class TestPolicyStatus:
    """Tests for get_opportunity_policy_status()."""

    def test_disallowed_status(self):
        """Provider with any 'disallowed' policy → status='disallowed'."""
        cat = load_catalog()
        for p_id in ["google", "github", "microsoft", "codex"]:
            p = get_provider(cat, p_id)
            if p and p.get("policy", {}).get("automation_allowed") == "disallowed":
                status = get_opportunity_policy_status(cat, p_id)
                assert status == "disallowed"
                break

    def test_unknown_status(self):
        """Provider with 'unknown' automation_allowed → status='unknown'."""
        cat = load_catalog()
        for p_id in ["groq", "deepseek"]:
            p = get_provider(cat, p_id)
            if p and p.get("policy", {}).get("automation_allowed") == "unknown":
                status = get_opportunity_policy_status(cat, p_id)
                assert status == "unknown"
                break

    def test_allowed_status(self):
        """Provider with all policies 'allowed' → status='allowed'."""
        cat = load_catalog()
        for p_id in ["claude", "kiro", "kilocode", "antigravity", "cursor"]:
            p = get_provider(cat, p_id)
            if p and p.get("policy", {}).get("automation_allowed") == "allowed":
                status = get_opportunity_policy_status(cat, p_id)
                assert status == "allowed"
                break

    def test_missing_provider_status_is_unknown(self):
        """Provider not in catalog → status='unknown' (never 'allowed')."""
        cat = load_catalog()
        status = get_opportunity_policy_status(cat, "nonexistent")
        assert status == "unknown"

    def test_policy_status_does_not_promote_unknown_to_allowed(self):
        """Explicit test of the critical invariant."""
        cat = load_catalog()
        # For all providers with unknown automation policy,
        # the opportunity status must be at most 'unknown', never 'allowed'
        for p in cat.get("providers", []):
            if p.get("policy", {}).get("automation_allowed") == "unknown":
                status = get_opportunity_policy_status(cat, p["id"])
                assert status != "allowed", \
                    f"Provider {p['id']} has unknown policy but status=allowed — BUG"
                assert status in ("unknown", "disallowed", "restricted")


class TestRiskScore:
    """Tests for policy_risk_score()."""

    def test_disallowed_risk_is_high(self):
        cat = load_catalog()
        for p_id in ["google", "github", "microsoft", "codex"]:
            p = get_provider(cat, p_id)
            if p and p.get("policy", {}).get("automation_allowed") == "disallowed":
                score = policy_risk_score(cat, p_id)
                assert score >= 25  # High risk
                break

    def test_unknown_risk_is_moderate(self):
        cat = load_catalog()
        for p_id in ["groq", "deepseek"]:
            p = get_provider(cat, p_id)
            if p and p.get("policy", {}).get("automation_allowed") == "unknown":
                score = policy_risk_score(cat, p_id)
                assert score >= 10  # Unknown is risky
                break

    def test_risk_score_in_range(self):
        cat = load_catalog()
        for p in cat.get("providers", []):
            score = policy_risk_score(cat, p["id"])
            assert 0 <= score <= 50


class TestPolicySummary:
    """Tests for policy_summary()."""

    def test_summary_returns_dict(self):
        cat = load_catalog()
        summary = policy_summary(cat, "groq")
        assert isinstance(summary, dict)
        assert "provider" in summary
        assert "provider_id" in summary
        assert "automation_allowed" in summary

    def test_summary_for_missing_provider(self):
        cat = load_catalog()
        summary = policy_summary(cat, "nonexistent")
        assert summary["provider_id"] == "nonexistent"


class TestPolicyCatalogConsistency:
    """Verify all catalog providers have consistent policy data."""

    def test_all_providers_have_policy(self):
        cat = load_catalog()
        for p in cat.get("providers", []):
            assert "policy" in p
            assert isinstance(p["policy"], dict)

    def test_all_providers_have_valid_automation_allowed(self):
        cat = load_catalog()
        valid_values = {"allowed", "disallowed", "restricted", "unknown"}
        for p in cat.get("providers", []):
            val = p.get("policy", {}).get("automation_allowed", "unknown")
            assert val in valid_values, \
                f"Provider {p['id']} has invalid automation_allowed: {val}"
