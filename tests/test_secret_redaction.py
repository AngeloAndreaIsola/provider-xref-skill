"""
test_secret_redaction.py — Regression tests for Phase 8 secret redaction invariants.

Security invariants (must never be violated):
  1. No password/API key ever appears in _invoke_workflow return values
  2. No secret ever appears in execution request JSON files
  3. No secret ever appears in registration_history.json
  4. The password field in workflow returns is always [REDACTED]
  5. 1Password item titles follow: "OmniRoute [hostname] Api Key"

Uses conftest.py fixtures: isolated_state, isolated_catalog (autouse), isolated_history.
"""
import sys
import os
import json
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch

from engine.executor import _invoke_workflow, _select_workflow, create_execution_request
from engine.catalog import load_catalog, get_provider
from engine.state import load_state
from engine import state as state_mod
from engine import registration as reg_mod
from engine import executor as exec_mod
from engine.utils import load_json


# ── Helpers ──────────────────────────────────────────────────────────────────

SECRET_PATTERN = re.compile(r'[A-Za-z0-9!@#$%^&*]{12,}')


def extract_strings_from_object(obj):
    """Recursively extract all string values from a nested object."""
    strings = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            strings.extend(extract_strings_from_object(v))
    elif isinstance(obj, list):
        for item in obj:
            strings.extend(extract_strings_from_object(item))
    return strings


def is_likely_secret(s):
    """Check if a string looks like a generated password/API key."""
    if not s or not isinstance(s, str):
        return False
    if s == "[REDACTED]":
        return False
    if s.startswith("<") and s.endswith(">"):
        return False
    non_secret_prefixes = ("Bearer ", "https://", "http://", "test_", "mock_", "fake_", "TEST_")
    if any(s.startswith(p) or s == p.rstrip("_") for p in non_secret_prefixes):
        return False
    # Must have special chars, digits, and uppercase to be a likely generated password
    if SECRET_PATTERN.match(s) and any(c in s for c in "!@#$%^&*") and any(c.isdigit() for c in s) and any(c.isupper() for c in s):
        return True
    return False


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def isolated_history(tmp_path, monkeypatch):
    """Redirect registration history to a temp file."""
    temp_history = tmp_path / "registration_history.json"
    temp_history.write_text(json.dumps({"history_version": 1, "entries": []}, indent=2))
    monkeypatch.setattr(reg_mod, "HISTORY_FILE", str(temp_history))
    yield temp_history


# ── Tests ────────────────────────────────────────────────────────────────────

class TestSecretRedactionInvokeWorkflow:
    """Phase 8 invariant: _invoke_workflow must never expose generated passwords."""

    def test_dry_run_no_password_exposed(self, isolated_state, isolated_catalog, isolated_history):
        """dry_run return value must not contain generated passwords."""
        catalog = load_catalog()
        provider = get_provider(catalog, "openai")
        assert provider is not None, "openai must be in fixture catalog"

        workflow = _select_workflow(provider)
        identity_id = "ident_002"  # test@example.com from full_sample_state

        request = {
            "provider_id": "openai",
            "identity_id": identity_id,
            "request_id": "test_dry_run",
        }
        result = _invoke_workflow(workflow, provider, request, dry_run=True)

        all_strings = extract_strings_from_object(result)
        secrets_found = [s for s in all_strings if is_likely_secret(s)]
        assert not secrets_found, (
            f"Generated password found in dry_run result: {secrets_found}"
        )

        pwd = result.get("password")
        assert pwd in (None, "[REDACTED]"), (
            f"password should be None or [REDACTED], got: {pwd}"
        )

    def test_dry_run_no_history_mutation(self, isolated_state, isolated_catalog, isolated_history):
        """dry_run must not write to registration history."""
        catalog = load_catalog()
        provider = get_provider(catalog, "openai")
        workflow = _select_workflow(provider)

        request = {
            "provider_id": "openai",
            "identity_id": "ident_002",
            "request_id": "test_nohistory",
        }
        _invoke_workflow(workflow, provider, request, dry_run=True)

        history = load_json(str(isolated_history))
        openai_entries = [e for e in history.get("entries", [])
                          if e.get("provider_id") == "openai"]
        assert len(openai_entries) == 0, (
            f"dry_run should not create history entries, found: {openai_entries}"
        )

    def test_dry_run_identity_none_no_crash(self, isolated_state, isolated_catalog, isolated_history):
        """dry_run must not crash when identity is not found in state."""
        catalog = load_catalog()
        provider = get_provider(catalog, "openai")
        workflow = _select_workflow(provider)

        # Use a non-existent identity ID — prep() should handle it
        request = {
            "provider_id": "openai",
            "identity_id": "nonexistent_identity",  # doesn't exist in fixture state
            "request_id": "test_none_identity",
        }
        result = _invoke_workflow(workflow, provider, request, dry_run=True)

        # Should not crash, should return actions
        assert "actions" in result
        assert result["mode"] == "dry_run"


class TestSecretRedactionFiles:
    """Phase 8 invariant: no secrets in persisted files."""

    def test_execution_request_no_secrets(self, isolated_state, isolated_catalog):
        """Execution request JSON must never contain secrets."""
        request = create_execution_request(
            operation="register_provider",
            provider_id="openai",
            identity_id="ident_002",
        )

        # Read the saved file
        req_path = os.path.join(str(exec_mod.EXECUTION_REQUESTS_DIR),
                                f"{request['request_id']}.json")
        with open(req_path) as f:
            serialized = f.read()

        assert "sk-" not in serialized
        assert "TEST_SECRET" not in serialized
        data = json.loads(serialized)
        all_strings = extract_strings_from_object(data)
        secrets = [s for s in all_strings if is_likely_secret(s)]
        assert not secrets, f"Secrets in execution request: {secrets}"

    def test_registration_history_no_secrets(self, isolated_state, isolated_catalog, isolated_history):
        """Registration history must never contain secrets."""
        catalog = load_catalog()
        provider = get_provider(catalog, "openai")
        workflow = _select_workflow(provider)

        request = {
            "provider_id": "openai",
            "identity_id": "ident_002",
            "request_id": "test_hist",
        }

        with patch("adapters.browser.api_key_flow") as mock_flow:
            mock_flow.return_value = {"provider_id": "openai", "actions": []}
            _invoke_workflow(workflow, provider, request, dry_run=False)

        history = load_json(str(isolated_history))
        for entry in history.get("entries", []):
            all_strings = extract_strings_from_object(entry)
            secrets = [s for s in all_strings if is_likely_secret(s)]
            assert not secrets, f"Secret in history entry: {secrets}"
            assert "password" not in entry, (
                f"password field in history entry: {entry.get('password')}"
            )


class TestNamingConvention:
    """Phase 8: 1Password items named 'OmniRoute [hostname] Api Key'."""

    def test_acquire_credentials_naming(self, isolated_state, isolated_catalog):
        """acquire_credentials must use 'OmniRoute [hostname] Api Key' naming."""
        from workflows.api_key import APIKeyWorkflow

        catalog = load_catalog()
        provider = get_provider(catalog, "openai")
        assert provider is not None

        workflow = APIKeyWorkflow()

        # Build opportunity with the same shape _invoke_workflow creates
        from engine.identity import canonical_identity_id
        opp = {
            "provider": "openai",
            "name": provider.get("name", "OpenAI"),
            "auth_type": "api_key",
            "policy_status": "allowed",
            "identity": "ident_002",
            "identity_label": None,
            "requirements": provider.get("identity_requirements", []),
            "verification_requirements": provider.get("verification_requirements", []),
            "free_quota": provider.get("free_tier", {}).get("quota", "Unknown"),
            "omniroute_support": provider.get("omniroute_support", {}),
            "downstream_count": 0,
        }

        prep = workflow.prepare(opp)

        with patch("workflows.api_key.create_login") as mock_create, \
             patch("workflows.api_key.find_login_item", return_value=None), \
             patch("workflows.api_key.find_api_key_item", return_value=None):
            mock_create.return_value = {"id": "test_item_id", "vault": "Personal"}
            fake_api_key = "TEST_SECRET_DO_NOT_LEAK_12345"
            fake_password = "TEST_PASSWORD_VALUE_123"
            result = workflow.acquire_credentials(opp, prep, fake_api_key, password=fake_password)

            call = mock_create.call_args
            title = call.kwargs.get("title") or call[1].get("title")
            assert title == "OmniRoute platform.openai.com Api Key", (
                f"Expected 'OmniRoute platform.openai.com Api Key', got: {title}"
            )

            # API key passed to 1Password but not in return value
            password = call.kwargs.get("password") or call[1].get("password")
            assert password == fake_api_key, "API key should be passed to 1Password"
            assert "api_key" not in result, "API key must not be in return value"
            assert "password" not in result, "Password must not be in return value"

    def test_naming_convention_anthropic(self, isolated_state, isolated_catalog):
        """Anthropic should use its hostname in the title."""
        from workflows.api_key import APIKeyWorkflow

        catalog = load_catalog()
        provider = get_provider(catalog, "anthropic")
        assert provider is not None

        workflow = APIKeyWorkflow()

        opp = {
            "provider": "anthropic",
            "name": provider.get("name", "Anthropic"),
            "auth_type": "api_key",
            "policy_status": "allowed",
            "identity": "ident_002",
            "identity_label": None,
            "requirements": provider.get("identity_requirements", []),
            "verification_requirements": provider.get("verification_requirements", []),
            "free_quota": provider.get("free_tier", {}).get("quota", "Unknown"),
            "omniroute_support": provider.get("omniroute_support", {}),
            "downstream_count": 0,
        }

        prep = workflow.prepare(opp)

        with patch("workflows.api_key.create_login") as mock_create, \
             patch("workflows.api_key.find_login_item", return_value=None), \
             patch("workflows.api_key.find_api_key_item", return_value=None):
            mock_create.return_value = {"id": "test_item_id", "vault": "Personal"}
            result = workflow.acquire_credentials(opp, prep, "TEST_SECRET", password="TEST_PASS")

            call = mock_create.call_args
            title = call.kwargs.get("title") or call[1].get("title")
            assert title.startswith("OmniRoute "), (
                f"Title should start with 'OmniRoute ', got: {title}"
            )
            assert title.endswith(" Api Key"), (
                f"Title should end with ' Api Key', got: {title}"
            )
            # Verify hostname is from the login_url/signup_url
            assert "claude.ai" in title, f"Should contain hostname, got: {title}"


class TestAccountLoginPersistence:
    """Phase 9F: Account login must be persisted to 1Password alongside API key."""

    def test_acquire_credentials_creates_both_login_and_apikey(self, isolated_state, isolated_catalog):
        """acquire_credentials must create both account login AND API key items."""
        from workflows.api_key import APIKeyWorkflow

        catalog = load_catalog()
        provider = get_provider(catalog, "groq")
        assert provider is not None

        workflow = APIKeyWorkflow()
        opp = {
            "provider": "groq",
            "name": provider.get("name", "Groq"),
            "auth_type": "api_key",
            "policy_status": "allowed",
            "identity": "ident_test",
            "identity_label": None,
            "requirements": provider.get("identity_requirements", []),
            "verification_requirements": provider.get("verification_requirements", []),
            "free_quota": provider.get("free_tier", {}).get("quota", "Unknown"),
            "omniroute_support": provider.get("omniroute_support", {}),
            "downstream_count": 0,
        }

        prep = workflow.prepare(opp)

        with patch("workflows.api_key.create_login") as mock_create, \
             patch("workflows.api_key.find_login_item", return_value=None), \
             patch("workflows.api_key.find_api_key_item", return_value=None):
            mock_create.return_value = {"id": "test_item_id", "vault": "Personal"}
            fake_api_key = "TEST_SECRET_API_KEY_123"
            fake_password = "TEST_PASSWORD_456"
            result = workflow.acquire_credentials(opp, prep, api_key=fake_api_key, password=fake_password)

            # Should have created TWO items: account login + API key
            assert mock_create.call_count == 2, (
                f"Expected 2 create_login calls, got {mock_create.call_count}"
            )

            # Check that both titles were used
            titles = [call.kwargs.get("title", call[1].get("title")) for call in mock_create.call_args_list]
            assert "Groq" in titles, f"Account login item 'Groq' not in titles: {titles}"
            assert any("OmniRoute" in t and t.endswith("Api Key") for t in titles), (
                f"API key item not in titles: {titles}"
            )

            # Verify no secrets in return value
            assert "password" not in result, "Password must not be in return value"
            assert "api_key" not in result, "API key must not be in return value"
            assert result["status"] == "success"

    def test_acquire_credentials_reuses_existing_login(self, isolated_state, isolated_catalog):
        """When account login already exists, it should be reused, not duplicated."""
        from workflows.api_key import APIKeyWorkflow

        catalog = load_catalog()
        provider = get_provider(catalog, "groq")
        workflow = APIKeyWorkflow()
        opp = {
            "provider": "groq",
            "name": provider.get("name", "Groq"),
            "auth_type": "api_key",
            "policy_status": "allowed",
            "identity": "ident_test",
            "identity_label": None,
            "requirements": [],
            "verification_requirements": [],
            "free_quota": "Unknown",
            "omniroute_support": {},
            "downstream_count": 0,
        }
        prep = workflow.prepare(opp)

        # Mock find_login_item to return an existing item
        existing_login = {"item_id": "existing_login_id", "vault": "Personal",
                          "title": "Groq", "username": "test@example.com", "tags": []}
        # Mock find_api_key_item to return None (no existing API key)
        with patch("workflows.api_key.find_login_item", return_value=existing_login), \
             patch("workflows.api_key.find_api_key_item", return_value=None), \
             patch("workflows.api_key.create_login") as mock_create:
            mock_create.return_value = {"id": "new_apikey_id", "vault": "Personal"}
            result = workflow.acquire_credentials(opp, prep, api_key="TEST_KEY", password="TEST_PASS")

            # Only ONE create_login call — for the API key, not the login
            assert mock_create.call_count == 1, (
                f"Should reuse existing login, only create API key. Got {mock_create.call_count} calls"
            )
            assert result["login_item_id"] == "existing_login_id"
            assert result["onepassword_item_id"] == "new_apikey_id"

    def test_acquire_credentials_reuses_existing_apikey(self, isolated_state, isolated_catalog):
        """When API key already exists, it should be reused, not duplicated."""
        from workflows.api_key import APIKeyWorkflow

        catalog = load_catalog()
        provider = get_provider(catalog, "groq")
        workflow = APIKeyWorkflow()
        opp = {
            "provider": "groq",
            "name": provider.get("name", "Groq"),
            "auth_type": "api_key",
            "policy_status": "allowed",
            "identity": "ident_test",
            "identity_label": None,
            "requirements": [],
            "verification_requirements": [],
            "free_quota": "Unknown",
            "omniroute_support": {},
            "downstream_count": 0,
        }
        prep = workflow.prepare(opp)

        existing_login = {"item_id": "existing_login_id", "vault": "Personal",
                          "title": "Groq", "username": "test@example.com", "tags": []}
        existing_apikey = {"item_id": "existing_apikey_id", "vault": "Personal",
                           "title": "OmniRoute api.groq.com Api Key", "tags": []}
        with patch("workflows.api_key.find_login_item", return_value=existing_login), \
             patch("workflows.api_key.find_api_key_item", return_value=existing_apikey), \
             patch("workflows.api_key.create_login") as mock_create:
            result = workflow.acquire_credentials(opp, prep, api_key="TEST_KEY", password="TEST_PASS")

            # NO create_login calls — both items reused
            assert mock_create.call_count == 0, (
                f"Should reuse both items. Got {mock_create.call_count} create calls"
            )
            assert result["login_item_id"] == "existing_login_id"
            assert result["onepassword_item_id"] == "existing_apikey_id"
            assert result["login_ref"]["reused"] is True
            assert result["apikey_ref"]["reused"] is True
