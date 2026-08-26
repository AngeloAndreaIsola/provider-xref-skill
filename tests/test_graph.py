"""
test_graph.py — Tests for the provider graph.

Constructs small deterministic fixtures and verifies:
  - identity discovery
  - provider-account discovery
  - unused identities
  - capability discovery
  - path tracing
  - duplicate opportunities
"""
import pytest

from engine.graph import ProviderGraph
from engine.state import default_state


class TestGraphConstruction:

    def test_graph_builds_from_empty_state(self, isolated_catalog):
        state = default_state()
        g = ProviderGraph(state, isolated_catalog)
        assert g.identities == {}
        assert g.external_accounts == {}
        assert g.provider_accounts == {}

    def test_graph_builds_from_full_state(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Test"},
        ]
        state["external_accounts"] = [
            {"id": "ea_1", "provider_id": "gmail", "identity_id": "ident_1",
             "status": "active", "created_at": "2025-01-01T00:00:00Z",
             "last_verified": "2025-01-01T00:00:00Z", "metadata": {}},
        ]
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": "ident_1",
             "external_account_id": "ea_1", "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        assert "ident_1" in g.identities
        assert "ea_1" in g.external_accounts
        assert "pa_1" in g.provider_accounts


class TestFindIdentities:

    def test_find_identities_all(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available"},
            {"id": "ident_2", "type": "phone", "value": "+155****4567",
             "status": "available"},
            {"id": "ident_3", "type": "google", "value": "user@gmail.com",
             "status": "active"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        identities = g.find_identities()
        assert len(identities) == 3

    def test_find_identities_empty(self, isolated_catalog):
        state = default_state()
        g = ProviderGraph(state, isolated_catalog)
        assert g.find_identities() == []


class TestFindProviderAccounts:

    def test_find_provider_accounts(self, isolated_catalog):
        state = default_state()
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": None,
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        accounts = g.find_provider_accounts()
        assert len(accounts) == 1
        assert accounts[0]["provider_id"] == "groq"

    def test_find_provider_accounts_none(self, isolated_catalog):
        state = default_state()
        g = ProviderGraph(state, isolated_catalog)
        assert g.find_provider_accounts() == []


class TestUnusedIdentities:

    def test_unused_identity(self, isolated_catalog):
        """Identity with no provider accounts is unused."""
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "unused@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Unused"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        unused = g.find_unused_identities()
        assert len(unused) == 1
        assert unused[0]["id"] == "ident_1"

    def test_used_identity_not_unused(self, isolated_catalog):
        """Identity linked to a provider account is NOT unused."""
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Used"},
        ]
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": "ident_1",
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        unused = g.find_unused_identities()
        assert len(unused) == 0

    def test_mixed_used_and_unused(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "active", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Used"},
            {"id": "ident_2", "type": "email", "value": "unused@example.com",
             "status": "available", "created_at": "2025-01-01T00:00:00Z",
             "last_seen": "2025-01-01T00:00:00Z", "label": "Unused"},
        ]
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": "ident_1",
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        unused = g.find_unused_identities()
        assert len(unused) == 1


class TestFindCapabilities:

    def test_find_capabilities_with_connected(self, isolated_catalog):
        state = default_state()
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": None,
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        state["capabilities"] = [
            {"id": "cap_1", "provider_id": "groq", "capabilities": ["text_generation"],
             "provider_account_id": "pa_1", "verified": True,
             "checked_at": "2025-01-01T00:00:00Z"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        caps = g.find_capabilities()
        assert len(caps) == 1
        assert caps[0]["provider_id"] == "groq"


class TestNullReferences:

    def test_null_identity_account(self, isolated_catalog):
        state = default_state()
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": None,
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        assert "pa_1" in g.provider_accounts
        assert g.provider_accounts["pa_1"]["identity_id"] is None


class TestMultipleIdentities:

    def test_multiple_identities_same_type(self, isolated_catalog):
        """Two email identities — both should be discoverable."""
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user1@example.com",
             "status": "available"},
            {"id": "ident_2", "type": "email", "value": "user2@example.com",
             "status": "available"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        identities = g.find_identities()
        assert len(identities) == 2


class TestFindPaths:

    def test_find_paths_single(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available"},
        ]
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": "ident_1",
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        # find_paths traverses identity -> provider_account (direct identity link)
        paths = g.find_paths("ident_1", "provider_account")
        assert len(paths) >= 1

    def test_find_paths_no_path(self, isolated_catalog):
        state = default_state()
        state["identities"] = [
            {"id": "ident_1", "type": "email", "value": "user@example.com",
             "status": "available"},
        ]
        g = ProviderGraph(state, isolated_catalog)
        paths = g.find_paths("ident_1", "provider_account")
        assert paths == []
