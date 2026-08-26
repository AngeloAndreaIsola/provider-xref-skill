"""
test_omniroute_adapter.py — Tests for the OmniRoute adapter.

All network calls are mocked — no real connections to the OmniRoute API.

Tests:
  - _get_token() token discovery from env, config file, .env
  - is_running() success and failure
  - get_connected_providers() parsing
  - discover_omniroute_state() discovery and normalization
  - No secrets in output
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from pathlib import Path

from adapters.omniroute import (
    _get_token, is_running, get_connected_providers,
    discover_omniroute_state, Adapter,
)
from engine.sync import discover_omniroute_state as sync_discover_omniroute_state


class TestTokenDiscovery:

    def test_token_from_env(self):
        with patch.dict("os.environ", {"OMNIR_TOKEN": "test_env_token_123"}):
            token = _get_token()
            assert token == "test_env_token_123"

    def test_token_from_config_file(self, tmp_path):
        """Token can be discovered from ~/.omniroute/config.json."""
        config = {
            "currentContext": "local-auth",
            "contexts": {
                "local-auth": {
                    "accessToken": "test_config_token_456",
                    "provider": "local",
                }
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        import adapters.omniroute as omn_mod
        with patch.object(omn_mod, "OMNIROUTE_CONFIG", config_file):
            token = _get_token()
        assert token == "test_config_token_456"

    def test_token_from_env_takes_priority(self, tmp_path):
        """Env var takes priority over config file."""
        config = {
            "contexts": {"local-auth": {"accessToken": "config_token"}}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        import adapters.omniroute as omn_mod
        with patch.object(omn_mod, "OMNIROUTE_CONFIG", config_file):
            with patch.dict("os.environ", {"OMNIR_TOKEN": "env_token"}):
                token = _get_token()
        assert token == "env_token"

    def test_token_none_when_no_source(self, tmp_path):
        """No token sources → None."""
        config_file = tmp_path / "nonexistent_config.json"

        import adapters.omniroute as omn_mod
        with patch.object(omn_mod, "OMNIROUTE_CONFIG", config_file):
            with patch.dict("os.environ", {}, clear=True):
                token = _get_token()
        assert token is None

    def test_token_never_printed(self):
        """Token value must never be logged or printed."""
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with patch.dict("os.environ", {"OMNIR_TOKEN": "SECRET_TOKEN_VALUE"}):
            with redirect_stdout(f):
                _get_token()
        output = f.getvalue()
        assert "SECRET_TOKEN_VALUE" not in output


class TestIsRunning:

    def test_is_running_success(self):
        """When API returns valid data, is_running should return True."""
        mock_response = [{"id": "conn_1", "provider": "openai", "authType": "apiKey"}]
        with patch("adapters.omniroute._api_request", return_value=mock_response):
            assert is_running() is True

    def test_is_running_failure(self):
        """When API returns None (network error), is_running should return False."""
        with patch("adapters.omniroute._api_request", return_value=None):
            assert is_running() is False

    def test_is_running_api_error(self):
        """When API returns error dict, is_running should return False."""
        with patch("adapters.omniroute._api_request", return_value={"error": "unauthorized"}):
            assert is_running() is False


class TestGetConnectedProviders:

    def test_parse_connections_response(self):
        """OmniRoute returns {connections: [...], total: N}."""
        mock_response = {
            "connections": [
                {"id": "conn_1", "provider": "openai", "authType": "apiKey"},
                {"id": "conn_2", "provider": "anthropic", "authType": "apiKey"},
            ],
            "total": 2
        }
        with patch("adapters.omniroute._api_request", return_value=mock_response):
            providers = get_connected_providers()
        assert len(providers) == 2
        assert providers[0]["provider"] == "openai"

    def test_parse_empty_response(self):
        mock_response = {"connections": [], "total": 0}
        with patch("adapters.omniroute._api_request", return_value=mock_response):
            providers = get_connected_providers()
        assert providers == []

    def test_parse_returns_empty_on_exception(self):
        """When _api_request returns None, get_connected_providers returns []."""
        with patch("adapters.omniroute._api_request", return_value=None):
            providers = get_connected_providers()
        assert providers == []

    def test_parse_list_response(self):
        """Some OmniRoute versions return a bare list."""
        mock_response = [
            {"id": "conn_1", "provider": "openai", "authType": "apiKey"},
        ]
        with patch("adapters.omniroute._api_request", return_value=mock_response):
            providers = get_connected_providers()
        assert len(providers) == 1


class TestDiscoverOmniRouteState:

    def test_discover_returns_dict(self):
        """discover_omniroute_state returns a dict with expected keys."""
        mock_providers = [
            {"id": "conn_1", "provider": "openai", "authType": "apiKey"},
        ]
        with patch("adapters.omniroute.get_connected_providers", return_value=mock_providers):
            result = sync_discover_omniroute_state()
        assert "all_omniroute_providers" in result
        assert "omniroute_only" in result
        assert "state_only" in result
        assert "matches" in result

    def test_no_secrets_in_output(self):
        """OmniRoute discovery output must never contain tokens."""
        mock_providers = [
            {"id": "conn_1", "provider": "openai", "authType": "apiKey"},
        ]
        with patch("adapters.omniroute.get_connected_providers", return_value=mock_providers):
            result = sync_discover_omniroute_state()
        serialized = json.dumps(result, default=str)
        assert "SECRET_TOKEN" not in serialized
        assert "Bearer" not in serialized

    def test_discover_with_state_provider_ids(self):
        """discover_omniroute_state accepts state_provider_ids for delta."""
        mock_providers = [
            {"id": "conn_1", "provider": "openai", "authType": "apiKey"},
            {"id": "conn_2", "provider": "groq", "authType": "apiKey"},
        ]
        with patch("adapters.omniroute.get_connected_providers", return_value=mock_providers):
            result = sync_discover_omniroute_state(state_provider_ids={"openai"})
        assert len(result["all_omniroute_providers"]) == 2
        assert "groq" in result["omniroute_only"]


class TestAdapterClass:

    def test_adapter_class_exists(self):
        adapter = Adapter()
        assert adapter is not None

    def test_adapter_is_running(self):
        adapter = Adapter()
        with patch("adapters.omniroute._api_request", return_value=[{"id": "conn_1"}]):
            assert adapter.is_running() is True

    def test_adapter_get_connected_providers(self):
        adapter = Adapter()
        with patch("adapters.omniroute.get_connected_providers", return_value=[{"id": "conn_1"}]):
            providers = adapter.get_connected_providers()
        assert isinstance(providers, list)
