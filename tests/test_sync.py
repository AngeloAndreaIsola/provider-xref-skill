"""
test_sync.py — Tests for the sync pipeline.

Tests the discover → normalize → compare → apply pipeline.

Uses mocked OmniRoute and 1Password adapters — no real network calls.

The sync process must be incremental: discover → normalize → compare → apply.
It must never blindly overwrite local state.
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from copy import deepcopy

from engine.sync import _normalize_omniroute, _compare, sync, _apply_changes
from engine.state import default_state
from engine.graph import ProviderGraph


class TestNormalizeOmniRoute:

    def test_normalize_single_provider(self, isolated_catalog):
        """Normalize a single OmniRoute provider discovery."""
        discovery = {
            "all_omniroute_providers": [
                {"id": "conn_1", "provider": "groq", "authType": "apiKey"},
            ],
        }
        normalized = _normalize_omniroute(discovery, isolated_catalog)
        assert len(normalized) == 1
        assert normalized[0]["provider_id"] == "groq"
        assert normalized[0]["status"] == "connected"
        assert normalized[0]["omniroute_connected"] is True
        assert normalized[0]["omniroute_account_id"] == "conn_1"

    def test_normalize_provider_not_in_catalog(self, isolated_catalog):
        """Provider in OmniRoute but not in catalog should still be normalized."""
        discovery = {
            "all_omniroute_providers": [
                {"id": "conn_1", "provider": "unknown_provider", "authType": "apiKey"},
            ],
        }
        normalized = _normalize_omniroute(discovery, isolated_catalog)
        assert len(normalized) == 1
        assert normalized[0]["provider_id"] == "unknown_provider"
        # When not in catalog, auth_type falls back to p.get("type", "unknown")
        assert normalized[0]["auth_type"] == "unknown"

    def test_normalize_multiple_providers(self, isolated_catalog):
        """Normalize multiple providers from OmniRoute."""
        discovery = {
            "all_omniroute_providers": [
                {"id": "conn_1", "provider": "groq", "authType": "apiKey"},
                {"id": "conn_2", "provider": "openai", "authType": "apiKey"},
            ],
        }
        normalized = _normalize_omniroute(discovery, isolated_catalog)
        assert len(normalized) == 2
        provider_ids = [n["provider_id"] for n in normalized]
        assert "groq" in provider_ids
        assert "openai" in provider_ids

    def test_normalize_empty_discovery(self, isolated_catalog):
        """Empty OmniRoute response → empty normalized list."""
        discovery = {"all_omniroute_providers": []}
        normalized = _normalize_omniroute(discovery, isolated_catalog)
        assert normalized == []


class TestCompare:

    def test_compare_new_provider_in_omniroute(self, isolated_catalog):
        """Provider in OmniRoute but not in state → add_provider_account change."""
        state = default_state()
        graph = ProviderGraph(state, isolated_catalog)

        omniroute_data = [
            {"provider_id": "groq", "status": "connected",
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "last_seen": "2025-01-01T00:00:00Z", "metadata": {},
             "auth_type": "api_key", "catalog_name": "Groq"},
        ]
        onepassword_data = []

        changes = _compare(state, graph, omniroute_data, onepassword_data, isolated_catalog)
        add_changes = [c for c in changes if c["type"] == "add_provider_account"]
        assert len(add_changes) >= 1
        assert add_changes[0]["provider_id"] == "groq"

    def test_compare_existing_provider_no_change(self, isolated_catalog):
        """Provider already in state and connected → minimal/no changes."""
        state = default_state()
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": None,
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        graph = ProviderGraph(state, isolated_catalog)

        omniroute_data = [
            {"provider_id": "groq", "status": "connected",
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "last_seen": "2025-01-01T00:00:00Z", "metadata": {},
             "auth_type": "api_key", "catalog_name": "Groq"},
        ]
        onepassword_data = []

        changes = _compare(state, graph, omniroute_data, onepassword_data, isolated_catalog)
        add_changes = [c for c in changes if c["type"] == "add_provider_account"]
        assert len(add_changes) == 0

    def test_compare_removed_provider_marked_disconnected(self, isolated_catalog):
        """Provider in state but not in OmniRoute → mark disconnected (not delete)."""
        state = default_state()
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": None,
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        graph = ProviderGraph(state, isolated_catalog)

        omniroute_data = []  # groq no longer in OmniRoute
        onepassword_data = []

        changes = _compare(state, graph, omniroute_data, onepassword_data, isolated_catalog)
        disconnect_changes = [c for c in changes if c["type"] == "update_provider_account"
                              and c.get("field") == "omniroute_connected"
                              and c.get("new_value") is False]
        assert len(disconnect_changes) >= 1

    def test_compare_preserves_existing_fields(self, isolated_catalog):
        """Compare should not produce add changes for existing providers."""
        state = default_state()
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": "ident_1",
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": {},
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]
        graph = ProviderGraph(state, isolated_catalog)

        omniroute_data = [
            {"provider_id": "groq", "status": "connected",
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "last_seen": "2025-01-01T00:00:00Z", "metadata": {},
             "auth_type": "api_key", "catalog_name": "Groq"},
        ]
        onepassword_data = []

        changes = _compare(state, graph, omniroute_data, onepassword_data, isolated_catalog)
        add_changes = [c for c in changes if c["type"] == "add_provider_account"
                       and c.get("provider_id") == "groq"]
        assert len(add_changes) == 0


class TestSyncApply:

    def test_sync_dry_run_does_not_modify(self, isolated_catalog):
        """Dry-run should not modify state."""
        state = default_state()

        mock_discovery = {"all_omniroute_providers": []}

        with patch("engine.sync.discover_omniroute_state", return_value=mock_discovery):
            with patch("engine.sync.get_adapter") as mock_get_adapter:
                mock_get_adapter.return_value.is_signed_in = MagicMock(return_value=False)
                original_count = len(state.get("provider_accounts", []))
                sync(state, isolated_catalog, dry_run=True)

        assert len(state.get("provider_accounts", [])) == original_count

    def test_sync_dry_run_reports_changes(self, isolated_catalog):
        """Dry-run should still report what WOULD change."""
        state = default_state()

        mock_discovery = {
            "all_omniroute_providers": [
                {"id": "conn_1", "provider": "groq", "authType": "apiKey"},
            ],
        }

        with patch("engine.sync.discover_omniroute_state", return_value=mock_discovery):
            with patch("engine.sync.get_adapter") as mock_get_adapter:
                mock_get_adapter.return_value.is_signed_in = MagicMock(return_value=False)
                result = sync(state, isolated_catalog, dry_run=True)

        assert len(result["added_provider_accounts"]) >= 1
        assert "groq" in result["added_provider_accounts"]

    def test_sync_apply_adds_provider(self, isolated_catalog):
        """Non-dry-run should add new provider accounts to state."""
        state = default_state()

        mock_discovery = {
            "all_omniroute_providers": [
                {"id": "conn_1", "provider": "groq", "authType": "apiKey"},
            ],
        }

        with patch("engine.sync.discover_omniroute_state", return_value=mock_discovery):
            with patch("engine.sync.get_adapter") as mock_get_adapter:
                mock_get_adapter.return_value.is_signed_in = MagicMock(return_value=False)
                sync(state, isolated_catalog, dry_run=False)

        assert len(state["provider_accounts"]) >= 1
        assert state["provider_accounts"][0]["provider_id"] == "groq"

    def test_sync_preserves_existing_data(self, isolated_catalog):
        """Sync must not delete existing provider accounts."""
        state = default_state()
        state["provider_accounts"] = [
            {"id": "pa_1", "provider_id": "groq", "identity_id": None,
             "external_account_id": None, "status": "connected",
             "auth_type": "api_key", "credential_ref": None,
             "omniroute_connected": True, "omniroute_account_id": "conn_1",
             "created_at": "2025-01-01T00:00:00Z", "last_verified": "2025-01-01T00:00:00Z"},
        ]

        mock_discovery = {
            "all_omniroute_providers": [
                {"id": "conn_1", "provider": "groq", "authType": "apiKey"},
                {"id": "conn_2", "provider": "openai", "authType": "apiKey"},
            ],
        }

        with patch("engine.sync.discover_omniroute_state", return_value=mock_discovery):
            with patch("engine.sync.get_adapter") as mock_get_adapter:
                mock_get_adapter.return_value.is_signed_in = MagicMock(return_value=False)
                result = sync(state, isolated_catalog, dry_run=True)

        # openai should be in added list
        assert "openai" in result["added_provider_accounts"]
        # groq should NOT be in added list (already exists)
        assert "groq" not in result["added_provider_accounts"]
