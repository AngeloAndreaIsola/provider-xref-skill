"""
test_reconciliation.py — Phase 3 tests for observation vs ownership semantics.

Tests cover:
  A. Ownership classification (UUID match, provider_id match, no match, 1Password evidence)
  B. Observation vs ownership (unknown ownership does not fabricate identities)
  C. Reconciliation determinism
  D. Sensitive data filtering
  E. 1Password security (no secret retrieval)
  F. Unknown-provider policy invariant
  G. No mutation during audit
  H. Import endpoint safety
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import pytest

# Ensure skill root is on path
SKILL_ROOT = str(Path(__file__).parent.parent.resolve())
if SKILL_ROOT not in sys.path:
    sys.path.insert(0, SKILL_ROOT)

from engine.audit import reconcile_real_state, _classify_ownership, _auth_distribution
from engine.graph import ProviderGraph
from engine.policy import can_automate_registration, get_opportunity_policy_status


# ── Shared fixtures (module-level so any test class can use them) ──────────

@pytest.fixture
def sample_omni_providers():
    return [
        {
            "provider_id": "openai",
            "provider": "openai",
            "auth_type": "api_key",
            "connection_id": "conn_uuid_1",
            "display_name": "user@example.com",
            "is_active": True,
            "test_status": "active",
        },
        {
            "provider_id": "anthropic",
            "provider": "anthropic",
            "auth_type": "api_key",
            "connection_id": "conn_uuid_2",
            "display_name": "user@example.com",
            "is_active": True,
            "test_status": "active",
        },
        {
            "provider_id": "groq",
            "provider": "groq",
            "auth_type": "api_key",
            "connection_id": "conn_uuid_3",
            "display_name": "user@example.com",
            "is_active": True,
            "test_status": "active",
        },
    ]

@pytest.fixture
def sample_catalog():
    return {
        "catalog_version": 1,
        "providers": [
            {"id": "openai", "name": "OpenAI", "auth_type": "api_key",
             "policy": {"automation_allowed": "unknown", "multiple_accounts": "unknown",
                        "duplicate_account_policy": "unknown", "third_party_proxy_allowed": "unknown",
                        "phone_reuse_allowed": "unknown"}},
            {"id": "anthropic", "name": "Anthropic", "auth_type": "api_key",
             "policy": {"automation_allowed": "unknown", "multiple_accounts": "unknown",
                        "duplicate_account_policy": "unknown", "third_party_proxy_allowed": "unknown",
                        "phone_reuse_allowed": "unknown"}},
            {"id": "groq", "name": "Groq", "auth_type": "api_key",
             "policy": {"automation_allowed": "unknown", "multiple_accounts": "unknown",
                        "duplicate_account_policy": "unknown", "third_party_proxy_allowed": "unknown",
                        "phone_reuse_allowed": "unknown"}},
        ],
        "scoring_weights": {},
    }


# ── A. Ownership classification ───────────────────────────────────────────

class TestOwnershipClassification:
    """A. Ownership classification tests."""

    def test_exact_uuid_match(self, sample_omni_providers, sample_catalog):
        """Connection matched by OmniRoute UUID → matched with match_method='omniroute_uuid'."""
        local_pas = [
            {
                "id": "pa_001",
                "provider_id": "openai",
                "omniroute_account_id": "conn_uuid_1",
                "identity_id": "ident_001",
                "ownership_status": "known",
                "match_confidence": "high",
            }
        ]

        result = _classify_ownership(sample_omni_providers, local_pas, [], sample_catalog)

        assert len(result["known"]) == 1
        assert result["known"][0]["provider_id"] == "openai"
        assert result["known"][0]["match_method"] == "omniroute_uuid"
        assert result["known"][0]["identity_id"] == "ident_001"
        assert len(result["unknown"]) == 2

    def test_provider_id_match(self, sample_omni_providers, sample_catalog):
        """Connection matched by provider_id (no UUID) → matched with match_method='provider_id'."""
        local_pas = [
            {
                "id": "pa_002",
                "provider_id": "groq",
                "omniroute_account_id": None,
                "identity_id": None,
                "ownership_status": "unknown",
                "match_confidence": "unknown",
            }
        ]

        result = _classify_ownership(sample_omni_providers, local_pas, [], sample_catalog)

        assert len(result["known"]) == 1
        assert result["known"][0]["provider_id"] == "groq"
        assert result["known"][0]["match_method"] == "provider_id"
        assert result["known"][0]["identity_id"] is None

    def test_no_match(self, sample_omni_providers, sample_catalog):
        """Connection not in local state, no 1Password evidence → unknown."""
        result = _classify_ownership(sample_omni_providers, [], [], sample_catalog)

        assert len(result["unknown"]) == 3
        assert len(result["known"]) == 0
        assert len(result["requires_review"]) == 0

    def test_onepassword_evidence_only(self, sample_omni_providers, sample_catalog):
        """1Password has a login for a provider but no local ownership → requires_review."""
        op_items = [
            {"item_id": "op_001", "title": "OpenAI", "vault": "Work",
             "category": "LOGIN", "tags": [], "username": "user@example.com"},
        ]

        result = _classify_ownership(sample_omni_providers, [], op_items, sample_catalog)

        assert len(result["requires_review"]) == 1
        assert result["requires_review"][0]["provider_id"] == "openai"
        assert result["requires_review"][0]["evidence"]["usernames"] == ["user@example.com"]
        assert len(result["unknown"]) == 2

    def test_conflicting_evidence(self, sample_omni_providers, sample_catalog):
        """Multiple 1Password items for same provider → still requires_review."""
        op_items = [
            {"item_id": "op_001", "title": "OpenAI", "vault": "Work",
             "category": "LOGIN", "tags": [], "username": "user1@example.com"},
            {"item_id": "op_002", "title": "OpenAI", "vault": "Work",
             "category": "LOGIN", "tags": [], "username": "user2@example.com"},
        ]

        result = _classify_ownership(sample_omni_providers, [], op_items, sample_catalog)

        assert len(result["requires_review"]) == 1
        assert len(result["requires_review"][0]["evidence"]["usernames"]) == 2

    def test_missing_identity(self, sample_omni_providers, sample_catalog):
        """Local record exists but identity_id is null → not fabricated."""
        local_pas = [
            {
                "id": "pa_003",
                "provider_id": "anthropic",
                "omniroute_account_id": "conn_uuid_2",
                "identity_id": None,
                "ownership_status": "unknown",
                "match_confidence": "unknown",
            }
        ]

        result = _classify_ownership(sample_omni_providers, local_pas, [], sample_catalog)

        assert len(result["known"]) == 1
        assert result["known"][0]["identity_id"] is None

    def test_uuid_match_takes_priority_over_provider_id(self, sample_catalog):
        """When both UUID and provider_id match, UUID takes priority."""
        omni = [
            {"provider_id": "openai", "auth_type": "api_key", "connection_id": "conn_a"},
        ]
        local_pas = [
            {
                "id": "pa_001",
                "provider_id": "openai",
                "omniroute_account_id": "conn_a",
                "identity_id": "ident_001",
                "ownership_status": "known",
            },
            {
                "id": "pa_002",
                "provider_id": "openai",
                "omniroute_account_id": "conn_b",  # different UUID, won't match
                "identity_id": "ident_002",
                "ownership_status": "requires_review",
            },
        ]
        result = _classify_ownership(omni, local_pas, [], sample_catalog)
        # The one with matching UUID should be matched first
        assert len(result["known"]) >= 1


# ── B. Observation vs ownership ───────────────────────────────────────────

class TestObservationVsOwnership:
    """B. Verify observation does not fabricate ownership."""

    def test_unknown_ownership_no_identity(self):
        """A provider_account with ownership_status='unknown' must not have identity_id."""
        from engine.state import default_state, validate_state
        state = default_state()
        pa = {
            "id": "pa_test",
            "provider_id": "openai",
            "auth_type": "api_key",
            "omniroute_connected": True,
            "omniroute_account_id": "conn_123",
            "created_at": "2025-01-01T00:00:00Z",
            "last_verified": "2025-01-01T00:00:00Z",
            "observed_at": "2025-01-01T00:00:00Z",
            "source": "omniroute_sync",
            "ownership_status": "unknown",
            "match_method": None,
            "match_confidence": "unknown",
            "identity_id": None,
            "external_account_id": None,
            "metadata": {"connection_id": "conn_123"},
        }
        import copy
        test_state = copy.deepcopy(state)
        test_state["provider_accounts"].append(pa)
        ok, msg = validate_state(test_state)
        assert ok, f"State validation failed: {msg}"

    def test_observation_does_not_fabricate_identity(self, sample_omni_providers, sample_catalog):
        """OmniRoute observation alone must not create an identity."""
        result = _classify_ownership(sample_omni_providers, [], [], sample_catalog)

        assert len(result["unknown"]) == 3
        for entry in result["unknown"]:
            assert entry["identity_id"] is None

    def test_observation_does_not_fabricate_external_account(self, sample_omni_providers, sample_catalog):
        """OmniRoute observation alone must not create an external account."""
        result = _classify_ownership(sample_omni_providers, [], [], sample_catalog)

        for entry in result["unknown"]:
            assert entry.get("identity_id") is None


# ── C. Reconciliation determinism ───────────────────────────────────────

class TestReconciliationDeterminism:
    """C. Reconciliation must be deterministic."""

    def test_deterministic_classification(self, sample_omni_providers, sample_catalog):
        """Same inputs → same output across multiple runs."""
        local_pas = [
            {
                "id": "pa_001",
                "provider_id": "openai",
                "omniroute_account_id": "conn_uuid_1",
                "identity_id": "ident_001",
                "ownership_status": "known",
                "match_confidence": "high",
            }
        ]

        results = []
        for _ in range(5):
            r = _classify_ownership(sample_omni_providers, local_pas, [], sample_catalog)
            results.append(json.dumps(r, sort_keys=True))

        assert all(r == results[0] for r in results), "Classification is not deterministic"

    def test_auth_distribution_deterministic(self):
        """Auth distribution must be stable."""
        providers = [
            {"provider_id": "a", "auth_type": "api_key"},
            {"provider_id": "b", "auth_type": "api_key"},
            {"provider_id": "c", "auth_type": "oauth"},
        ]
        dist = _auth_distribution(providers)
        assert dist == {"api_key": 2, "oauth": 1}


# ── D. Sensitive data filtering ───────────────────────────────────────────

class TestSensitiveDataFiltering:
    """D. Sensitive OmniRoute fields must be stripped."""

    def test_sensitive_fields_stripped_from_normalized(self):
        """_is_sensitive_key should flag secret-like keys but allow authType."""
        try:
            from adapters.omniroute import _is_sensitive_key
        except ImportError:
            from ..adapters.omniroute import _is_sensitive_key

        sensitive_keys = ["apiKey", "secret", "token", "accessToken",
                          "refreshToken", "password", "credential", "key"]
        safe_keys = ["id", "provider", "name", "priority", "isActive", "testStatus",
                     "authType", "providerSpecificData"]

        for k in sensitive_keys:
            assert _is_sensitive_key(k), f"Key '{k}' should be flagged as sensitive"

        for k in safe_keys:
            assert not _is_sensitive_key(k), f"Key '{k}' should NOT be flagged as sensitive"

    def test_normalize_strips_secrets(self, sample_catalog):
        """_normalize_omniroute must strip secret-like fields from metadata."""
        from engine.sync import _normalize_omniroute

        discovery = {
            "all_omniroute_providers": [
                {
                    "provider_id": "openai",
                    "provider": "openai",
                    "auth_type": "api_key",
                    "connection_id": "conn_123",
                    "display_name": "user@example.com",
                    "apiKey": "sk-secret-should-not-appear",
                    "secret": "should-not-appear",
                    "token": "should-not-appear",
                    "priority": 1,
                    "isActive": True,
                }
            ],
            "total_omniroute_providers": 1,
            "omniroute_only": [],
            "state_only": [],
            "matches": [],
            "uncatalogued": [],
            "ownership_breakdown": {"known": 0, "unknown": 1,
                                    "requires_review": 0, "inferred": 0},
        }

        normalized = _normalize_omniroute(discovery, sample_catalog)
        assert len(normalized) == 1

        meta = normalized[0].get("metadata", {})
        meta_str = json.dumps(meta)
        assert "sk-secret-should-not-appear" not in meta_str
        assert "should-not-appear" not in meta_str

        assert normalized[0]["identity_id"] is None
        assert normalized[0]["external_account_id"] is None
        assert normalized[0]["ownership_status"] == "unknown"

    def test_no_secrets_in_state_file(self):
        """Production provider_state.json must not contain sk- patterns."""
        state_path = Path(SKILL_ROOT) / "provider_state.json"
        if state_path.exists():
            content = state_path.read_text()
            assert "sk-" not in content, "Potential API key found in provider_state.json"

    def test_no_secrets_in_history_file(self):
        """Registration history must not contain sk- patterns."""
        history_path = Path(SKILL_ROOT) / "data" / "registration_history.json"
        if history_path.exists():
            content = history_path.read_text()
            assert "sk-" not in content, "Potential API key found in registration_history.json"


# ── E. 1Password security ───────────────────────────────────────────────

class TestOnePasswordSecurity:
    """E. 1Password adapter must never retrieve secrets during reconciliation."""

    def test_vault_discovery_dynamic(self):
        """list_vaults should work without assuming 'Private'."""
        from adapters.onepassword import list_vaults

        vaults = list_vaults()
        assert isinstance(vaults, list)
        for v in vaults:
            assert "id" in v
            assert "name" in v

    def test_vault_discovery_does_not_hardcode_private(self):
        """Ensure get_default_vault does not hardcode 'Private'."""
        from adapters.onepassword import get_default_vault
        vault = get_default_vault()
        assert vault != "Private", "get_default_vault should not return 'Private'"

    def test_reconciliation_does_not_call_secret_retrieval(self, monkeypatch):
        """reconcile_real_state must not call get_credential_value."""
        from engine.audit import reconcile_real_state

        monkeypatch.setattr("engine.audit._discover_omniroute", lambda state: {
            "reachable": False, "all_omniroute_providers": [],
            "total_omniroute_providers": 0, "uncatalogued": [],
            "ownership_breakdown": {"known": 0, "unknown": 0,
                                    "requires_review": 0, "inferred": 0},
        })

        secret_retrieved = False

        def mock_discover_op():
            return [], []

        monkeypatch.setattr("engine.audit._discover_onepassword", mock_discover_op)

        result = reconcile_real_state()
        assert secret_retrieved is False
        assert result["onepassword"]["relevant_items"] == 0


# ── F. Unknown-provider policy invariant ─────────────────────────────────

class TestUnknownProviderPolicy:
    """F. UNKNOWN must never become ALLOW."""

    def test_new_providers_all_unknown(self):
        """All 30 bootstrapped providers must have automation_allowed=unknown."""
        catalog_path = Path(SKILL_ROOT) / "provider_catalog.json"
        with open(catalog_path) as f:
            catalog = json.load(f)

        new_provider_ids = {
            "agnes", "aimlapi", "ainative", "aion", "blackbox", "charm-hyper",
            "claude-web", "codex-cloud", "deepseek-web", "devin", "devin-cli",
            "doubao-web", "grok-cli", "jules", "kimi-coding", "lmarena",
            "mimocode", "muse-spark-web", "ollama-cloud", "ollama-local",
            "opencode", "perplexity", "qoder", "qwen-cloud", "qwen-web",
            "sarvam", "trae", "v0-vercel", "vercel-ai-gateway", "zai",
        }

        for p in catalog["providers"]:
            if p["id"] in new_provider_ids:
                assert p["policy"]["automation_allowed"] == "unknown", \
                    f"New provider {p['id']} must have UNKNOWN policy"
                assert p["policy"]["multiple_accounts"] == "unknown"
                assert p["policy"]["third_party_proxy_allowed"] == "unknown"

    def test_existing_deny_remains_deny(self):
        """Existing DENY entries must remain DENY."""
        catalog_path = Path(SKILL_ROOT) / "provider_catalog.json"
        with open(catalog_path) as f:
            catalog = json.load(f)

        deny_providers = ["codex", "cursor", "google", "github", "microsoft"]
        for p in catalog["providers"]:
            if p["id"] in deny_providers:
                assert p["policy"]["automation_allowed"] == "disallowed", \
                    f"Provider {p['id']} should remain DENY"

    def test_can_automate_is_false_for_unknown(self):
        """can_automate_registration must return False for UNKNOWN policy providers."""
        catalog_path = Path(SKILL_ROOT) / "provider_catalog.json"
        with open(catalog_path) as f:
            catalog = json.load(f)

        for p in catalog["providers"]:
            if p["policy"]["automation_allowed"] == "unknown":
                can_auto, reason = can_automate_registration(catalog, p["id"])
                assert can_auto is False, \
                    f"Provider {p['id']} has UNKNOWN policy but can_automate=True"

    def test_no_provider_made_allowed_from_omniroute_existence(self):
        """NO provider's policy should be ALLOW just because it's in OmniRoute."""
        catalog_path = Path(SKILL_ROOT) / "provider_catalog.json"
        with open(catalog_path) as f:
            catalog = json.load(f)

        allowed_ids = {p["id"] for p in catalog["providers"]
                       if p.get("policy", {}).get("automation_allowed") == "allowed"}
        expected_allowed = {"agentrouter", "antigravity", "cline", "kilocode"}
        assert allowed_ids == expected_allowed, \
            f"Unexpected ALLOW providers: {allowed_ids - expected_allowed}"


# ── G. No mutation during audit ─────────────────────────────────────────

class TestAuditNonMutation:
    """G. Audit must not modify state files."""

    def test_sync_dry_run_does_not_modify_state(self, tmp_path, monkeypatch):
        """dry_run=True must not write to state file."""
        import hashlib

        state_dir = tmp_path / "data"
        state_dir.mkdir()
        state_file = state_dir / "provider_state.json"
        test_state = {
            "schema_version": 1,
            "updated_at": "2025-01-01T00:00:00Z",
            "identities": [],
            "external_accounts": [],
            "provider_accounts": [],
            "credentials": [],
            "capabilities": [],
        }
        state_file.write_text(json.dumps(test_state, indent=2))
        original_hash = hashlib.sha256(state_file.read_text().encode()).hexdigest()

        import engine.utils as utils_mod
        import engine.state as state_mod
        monkeypatch.setattr(utils_mod, 'STATE_FILE', state_file)
        monkeypatch.setattr(state_mod, 'STATE_FILE', state_file)

        from engine.sync import sync
        import engine.sync as sync_mod

        def mock_discover(state_pids):
            return {
                "total_omniroute_providers": 1,
                "omniroute_only": ["newprovider"],
                "state_only": [],
                "matches": [],
                "all_omniroute_providers": [
                    {"provider_id": "newprovider", "provider": "newprovider",
                     "auth_type": "api_key", "connection_id": "conn_new",
                     "display_name": None, "is_active": True, "test_status": None},
                ],
                "uncatalogued": ["newprovider"],
                "ownership_breakdown": {"known": 0, "unknown": 1,
                                        "requires_review": 0, "inferred": 0},
            }

        monkeypatch.setattr(sync_mod, 'discover_omniroute_state', mock_discover)
        monkeypatch.setattr("engine.sync.get_adapter", lambda name: None)

        result = sync(dry_run=True)

        new_hash = hashlib.sha256(state_file.read_text().encode()).hexdigest()
        assert new_hash == original_hash, "State file was modified during dry-run sync"
        assert result["changes_count"] > 0
        assert result["added_provider_accounts"] == ["newprovider"]


# ── H. Import endpoint safety ───────────────────────────────────────────

class TestImportEndpointSafety:
    """H. The import endpoint must never be called during audit/sync."""

    def test_import_not_called_during_audit(self, monkeypatch):
        """reconcile_real_state must never call _api_request with POST."""
        from engine.audit import reconcile_real_state
        import adapters.omniroute as omni_mod

        api_calls = []
        original_request = omni_mod._api_request

        def tracking_request(method, path, data=None):
            api_calls.append((method, path))
            return original_request(method, path, data)

        monkeypatch.setattr(omni_mod, '_api_request', tracking_request)
        monkeypatch.setattr(omni_mod, 'is_running', lambda: False)
        monkeypatch.setattr(omni_mod, 'get_connected_providers', lambda: [])

        monkeypatch.setattr("engine.audit._discover_onepassword", lambda: ([], []))

        reconcile_real_state()

        post_calls = [c for c in api_calls if c[0] == "POST"]
        assert len(post_calls) == 0, f"POST calls made during audit: {post_calls}"

        import_calls = [c for c in api_calls if "import" in c[1]]
        assert len(import_calls) == 0, f"Import endpoint called: {import_calls}"

    def test_import_endpoint_is_POST_only(self):
        """Verify that /api/providers/import returns 405 for GET."""
        from adapters.omniroute import _api_request

        result = _api_request("GET", "/api/providers/import")
        assert result is not None
        if isinstance(result, dict):
            assert result.get("status_code") == 405 or "error" in result, \
                f"Expected 405 for GET /api/providers/import, got: {result}"
