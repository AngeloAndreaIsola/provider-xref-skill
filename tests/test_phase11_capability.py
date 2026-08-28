"""
test_phase11_capability.py — Phase 11 data-driven provider capability model.

Verifies:
  * capability parsing from catalog data (registration / extraction blocks)
  * default/derived values when blocks are absent
  * policy vs support separation
  * registration readiness classification
  * auth methods
  * browser requirements
  * human checkpoint requirements
  * credential type
  * extraction configuration
  * backward compatibility for providers without the new blocks
  * catalog schema validation (new optional blocks)
"""
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from engine.capability import (
    build_capability,
    build_capabilities,
    can_register,
    get_auth_methods,
    requires_browser,
    can_require_human_checkpoint,
    expected_credential_type,
    can_extract_credential,
    is_ready_for_automation,
    POLICY_ALLOWED, POLICY_UNKNOWN, POLICY_DISALLOWED,
    SUPPORT_SUPPORTED, SUPPORT_UNKNOWN,
    READINESS_READY, READINESS_NEEDS_REVIEW, READINESS_BLOCKED_POLICY,
    READINESS_UNSUPPORTED, READINESS_UNKNOWN,
    REG_STATE_BLOCKED, REG_STATE_ELIGIBLE, REG_STATE_UNKNOWN,
)
from engine.catalog import load_catalog
import jsonschema
from engine.utils import load_json


# ── Minimal catalogs (isolate capability logic from the 79-provider file) ──

CATALOG_FULL = {
    "catalog_version": 1,
    "providers": [
        {
            "id": "groq", "name": "Groq", "auth_type": "api_key",
            "identity_requirements": ["email"], "identity_relationships": ["google", "github"],
            "omniroute_support": {"supported": True, "type": "direct"},
            "policy": {"automation_allowed": "allowed", "multiple_accounts": "restricted"},
            "verification_requirements": ["email", "phone"],
            "cascades_to": [],
            "registration": {
                "methods": ["api_key", "google", "github"],
                "browser_required": False,
                "human_checkpoint_possible": True,
                "credential_type": "api_key",
                "checkpoint_types": ["email_verification", "phone_verification", "manual_oauth"],
            },
            "extraction": {"automation_supported": True, "rules_ref": "groq"},
        },
        {
            "id": "claude", "name": "Anthropic Claude", "auth_type": "oauth",
            "identity_requirements": ["email"], "identity_relationships": [],
            "omniroute_support": {"supported": True, "type": "direct"},
            "policy": {"automation_allowed": "unknown"},
            "verification_requirements": ["email"],
            "cascades_to": [],
            # NO registration/extraction blocks -> derived defaults
        },
        {
            # Policy disallows -> blocked regardless of support
            "id": "evilcorp", "name": "EvilCorp", "auth_type": "api_key",
            "omniroute_support": {"supported": True},
            "policy": {"automation_allowed": "disallowed"},
            "cascades_to": [],
        },
        {
            "id": "fullyok", "name": "Fully OK", "auth_type": "api_key",
            "identity_requirements": ["email"], "identity_relationships": [],
            "omniroute_support": {"supported": True, "type": "direct"},
            "policy": {
                "automation_allowed": "allowed", "multiple_accounts": "allowed",
                "duplicate_account_policy": "allowed", "third_party_proxy_allowed": "allowed",
                "phone_reuse_allowed": "allowed",
            },
            "verification_requirements": ["email"],
            "cascades_to": [],
            "registration": {
                "methods": ["api_key"],
                "browser_required": False,
                "human_checkpoint_possible": True,
                "credential_type": "api_key",
                "checkpoint_types": ["email_verification"],
            },
            "extraction": {"automation_supported": True, "rules_ref": "deepseek"},
        },
        {
            # No workflow, no omniroute -> support unknown
            "id": "mystery", "name": "Mystery", "auth_type": "unknown",
            "policy": {"automation_allowed": "unknown"},
            "cascades_to": [],
        },
    ],
}


class TestCapabilityParsing:

    def test_parses_registration_block(self):
        cap = build_capability("groq", CATALOG_FULL)
        assert cap.browser_required is False
        assert cap.human_checkpoint_possible is True
        assert cap.credential_type == "api_key"
        assert "email_verification" in cap.checkpoint_types

    def test_parses_extraction_block(self):
        cap = build_capability("groq", CATALOG_FULL)
        assert cap.extraction_supported is True
        assert cap.credential_state == "extractable"

    def test_explicit_registration_overrides_derivation(self):
        # groq block says browser_required=False even though it has identity_relationships
        cap = build_capability("groq", CATALOG_FULL)
        assert cap.browser_required is False


class TestDefaultsAndDerivedValues:

    def test_missing_blocks_derive_conservative_defaults(self):
        cap = build_capability("claude", CATALOG_FULL)
        # No blocks -> derived, not crash
        assert cap.support_status == SUPPORT_SUPPORTED  # oauth workflow exists
        assert cap.browser_required is True  # oauth needs browser
        assert cap.human_checkpoint_possible is True  # oauth + verification reqs
        assert cap.credential_type == "oauth_token"
        assert "email_verification" in cap.checkpoint_types

    def test_unknown_provider_is_safe(self):
        cap = build_capability("does-not-exist", CATALOG_FULL)
        assert cap.policy_status == POLICY_UNKNOWN
        assert cap.support_status == SUPPORT_UNKNOWN
        assert cap.registration_state == REG_STATE_UNKNOWN
        assert cap.can_register_now is False

    def test_derived_auth_methods_from_auth_type(self):
        cap = build_capability("groq", CATALOG_FULL)
        assert "api_key" in cap.auth_methods
        # registration block methods win
        assert set(cap.auth_methods) == {"api_key", "google", "github"}


class TestPolicyVsSupportSeparation:

    def test_policy_and_support_are_independent_dimensions(self):
        allowed_supported = build_capability("fullyok", CATALOG_FULL)
        assert allowed_supported.policy_status == POLICY_ALLOWED
        assert allowed_supported.support_status == SUPPORT_SUPPORTED

    def test_support_does_not_grant_policy(self):
        # mystery: workflow default (oauth) exists so support=supported, but
        # policy is unknown -> still NOT ready. Support never grants policy.
        cap = build_capability("mystery", CATALOG_FULL)
        assert cap.policy_status == POLICY_UNKNOWN
        assert cap.can_register_now is False  # unknown policy => never auto-ready


class TestRegistrationReadiness:

    def test_allowed_and_supported_is_ready(self):
        cap = build_capability("fullyok", CATALOG_FULL)
        assert cap.registration_readiness == READINESS_READY
        assert cap.can_register_now is True

    def test_disallowed_policy_blocks_registration(self):
        cap = build_capability("evilcorp", CATALOG_FULL)
        assert cap.policy_status == POLICY_DISALLOWED
        assert cap.registration_state == REG_STATE_BLOCKED
        assert cap.registration_readiness == READINESS_BLOCKED_POLICY
        assert cap.can_register_now is False
        assert not cap.is_ready_for_automation()

    def test_unknown_policy_needs_review_not_auto(self):
        cap = build_capability("claude", CATALOG_FULL)
        assert cap.policy_status == POLICY_UNKNOWN
        assert cap.registration_readiness == READINESS_NEEDS_REVIEW
        assert cap.can_register_now is False  # must NOT auto-allow unknown policy


class TestAuthMethods:

    def test_explicit_methods(self):
        assert get_auth_methods("groq", CATALOG_FULL) == ["api_key", "google", "github"]

    def test_derived_for_oauth(self):
        cap = build_capability("claude", CATALOG_FULL)
        assert "oauth" in cap.auth_methods


class TestBrowserRequirements:

    def test_oauth_requires_browser_by_default(self):
        assert requires_browser("claude", CATALOG_FULL) is True

    def test_api_key_no_oauth_rel_does_not_require_browser(self):
        assert requires_browser("groq", CATALOG_FULL) is False


class TestCheckpointRequirements:

    def test_checkpoint_possible_flag(self):
        assert can_require_human_checkpoint("groq", CATALOG_FULL) is True
        assert can_require_human_checkpoint("claude", CATALOG_FULL) is True

    def test_checkpoint_types_present(self):
        cap = build_capability("groq", CATALOG_FULL)
        assert "phone_verification" in cap.checkpoint_types


class TestCredentialType:

    def test_expected_credential_type(self):
        assert expected_credential_type("groq", CATALOG_FULL) == "api_key"
        assert expected_credential_type("claude", CATALOG_FULL) == "oauth_token"


class TestExtractionConfiguration:

    def test_extraction_supported_true(self):
        assert can_extract_credential("groq", CATALOG_FULL) is True

    def test_extraction_derived_from_rule_catalog(self):
        # fullyok uses rules_ref='deepseek' which exists in PROVIDER_EXTRACTION_RULES
        cap = build_capability("fullyok", CATALOG_FULL)
        assert cap.extraction_supported is True

    def test_extraction_unsupported_when_no_rule(self):
        # mystery has auth_type unknown and no rule -> not extractable
        cap = build_capability("mystery", CATALOG_FULL)
        assert cap.extraction_supported is False


class TestBackwardCompatibility:

    def test_real_catalog_validates_with_optional_blocks(self):
        cat = load_catalog()
        schema = load_json(SKILL_ROOT / "schemas" / "provider_catalog.schema.json")
        jsonschema.validate(instance=cat, schema=schema)  # must not raise

    def test_real_providers_build_without_error(self):
        cat = load_catalog()
        caps = build_capabilities(cat)
        assert len(caps) == len(cat["providers"])
        # Every capability resolves to a valid state vocabulary
        for pid, cap in caps.items():
            assert cap.registration_readiness in (
                READINESS_READY, READINESS_NEEDS_REVIEW,
                READINESS_BLOCKED_POLICY, READINESS_UNSUPPORTED, READINESS_UNKNOWN,
            )

    def test_provider_without_new_blocks_still_resolves(self):
        # openai/groq/claude/cloudflare-ai now have blocks; pick one without
        cat = load_catalog()
        some_pid = next(p["id"] for p in cat["providers"]
                        if "registration" not in p and "extraction" not in p)
        cap = build_capability(some_pid, cat)
        assert cap.provider_id == some_pid
        assert isinstance(cap.to_dict(), dict)


class TestRealRepresentativeProviders:

    def test_groq_claude_openai_cloudflare_ai_capabilities(self):
        cat = load_catalog()
        for pid in ["groq", "claude", "openai", "cloudflare-ai"]:
            cap = build_capability(pid, cat)
            assert cap.name
            # openai was added in this phase; claude is the Anthropic entry
            assert cap.auth_type in ("api_key", "oauth")
            assert cap.credential_type is not None
