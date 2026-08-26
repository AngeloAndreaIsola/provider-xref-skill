"""
conftest.py — shared fixtures and path setup for provider-xref tests.
"""
import sys
import os
import json
import copy
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# ── Path setup: ensure the skill root is on sys.path ─────────────────────
SKILL_ROOT = str(Path(__file__).parent.parent.resolve())
if SKILL_ROOT not in sys.path:
    sys.path.insert(0, SKILL_ROOT)

# ── Fixture paths ────────────────────────────────────────────────────────
FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture by name (relative to fixtures/)."""
    path = FIXTURE_DIR / name
    with open(path) as f:
        return json.load(f)


# ── Identity fixtures ────────────────────────────────────────────────────

@pytest.fixture
def sample_phone_identity():
    return {
        "id": "ident_001",
        "type": "phone",
        "value": "+15551234567",
        "label": "Test phone",
        "status": "available",
        "created_at": "2025-06-01T10:00:00Z",
        "last_seen": "2025-06-01T10:00:00Z",
    }


@pytest.fixture
def sample_email_identity():
    return {
        "id": "ident_002",
        "type": "email",
        "value": "test@example.com",
        "label": "Test email",
        "status": "available",
        "created_at": "2025-06-01T10:00:00Z",
        "last_seen": "2025-06-01T10:00:00Z",
        "verification": {"email_verified": True},
    }


@pytest.fixture
def sample_google_identity():
    return {
        "id": "ident_003",
        "type": "google",
        "value": "googleuser@gmail.com",
        "label": "Google account",
        "status": "active",
        "created_at": "2025-06-01T12:00:00Z",
        "last_seen": "2025-06-01T12:00:00Z",
    }


# ── Entity fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def sample_external_account(sample_phone_identity):
    return {
        "id": "ext_001",
        "identity_id": "ident_001",
        "provider": "google",
        "status": "active",
        "username": "googleuser@gmail.com",
        "email": "googleuser@gmail.com",
        "auth_method": "oauth",
        "created_at": "2025-06-01T11:00:00Z",
        "last_seen": "2025-06-01T11:00:00Z",
        "credential_ref": None,
        "metadata": {},
    }


@pytest.fixture
def sample_provider_account(sample_external_account):
    return {
        "id": "pa_001",
        "provider_id": "openai",
        "identity_id": "ident_001",
        "external_account_id": "ext_001",
        "status": "connected",
        "auth_type": "api_key",
        "credential_ref": {
            "backend": "1password",
            "vault": "Personal",
            "item_id": "item_abc123",
            "field": "credential",
        },
        "omniroute_connected": True,
        "omniroute_account_id": "conn_xyz",
        "created_at": "2025-06-01T13:00:00Z",
        "last_verified": "2025-06-01T13:00:00Z",
        "last_seen": "2025-06-01T13:00:00Z",
        "metadata": {},
    }


@pytest.fixture
def sample_credential(sample_provider_account):
    return {
        "id": "cred_001",
        "type": "api_key",
        "backend": "1password",
        "vault": "Personal",
        "item_id": "item_abc123",
        "field": "credential",
        "provider_account_id": "pa_001",
        "status": "active",
        "created_at": "2025-06-01T13:00:00Z",
        "last_rotated": None,
    }


@pytest.fixture
def sample_capability():
    return {
        "id": "cap_001",
        "name": "llm_api",
        "provider_account_id": "pa_001",
        "capabilities": ["text_generation", "json_mode"],
        "verified": True,
        "checked_at": "2025-06-01T13:30:00Z",
    }


@pytest.fixture
def full_sample_state(sample_phone_identity, sample_email_identity,
                       sample_google_identity, sample_external_account,
                       sample_provider_account, sample_credential,
                       sample_capability):
    """A complete, valid provider_state.json with linked entities."""
    return {
        "schema_version": 1,
        "updated_at": "2025-06-01T13:30:00Z",
        "identities": [
            dict(sample_phone_identity),
            dict(sample_email_identity),
            dict(sample_google_identity),
        ],
        "external_accounts": [
            dict(sample_external_account),
        ],
        "provider_accounts": [
            dict(sample_provider_account),
        ],
        "credentials": [
            dict(sample_credential),
        ],
        "capabilities": [
            dict(sample_capability),
        ],
    }


# ─── Isolated state — patches STATE_FILE to use a temp directory ──────────

@pytest.fixture
def isolated_state(tmp_path, full_sample_state):
    """
    Write sample state to a temp file and patch all state path constants
    to point there. Tests get isolation without touching real files.
    """
    import engine.utils as utils_mod
    import engine.state as state_mod

    state_dir = tmp_path / ".hermes" / "skills" / "provider-xref"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "provider_state.json"
    state_file.write_text(json.dumps(full_sample_state, indent=2))

    # Patch STATE_FILE in both utils and state modules (they import it)
    with patch.object(utils_mod, 'STATE_FILE', state_file):
        with patch.object(state_mod, 'STATE_FILE', state_file):
            # Also patch load_state in modules that imported it directly
            yield full_sample_state


@pytest.fixture
def isolated_catalog(tmp_path):
    """Patch catalog loading to use a temp catalog file based on the fixture."""
    import engine.utils as utils_mod
    import engine.catalog as catalog_mod

    catalog_dir = tmp_path / ".hermes" / "skills" / "provider-xref"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    catalog_file = catalog_dir / "provider_catalog.json"

    # Load the fixture catalog
    fixture_catalog = load_fixture("catalog/basic_catalog.json")
    catalog_file.write_text(json.dumps(fixture_catalog, indent=2))

    with patch.object(utils_mod, 'CATALOG_FILE', catalog_file):
        with patch.object(catalog_mod, 'CATALOG_FILE', catalog_file):
            yield fixture_catalog


# ─── Mock data fixtures ──────────────────────────────────────────────────

@pytest.fixture
def mock_omniroute():
    """Mock OmniRoute adapter responses."""
    return {
        "mock_providers": [
            {
                "id": "conn_001",
                "provider": "openai",
                "authType": "apiKey",
                "name": "user@example.com",
                "priority": 1,
                "isActive": True,
                "testStatus": "active",
                "createdAt": "2025-06-01T00:00:00Z",
                "updatedAt": "2025-06-01T00:00:00Z",
            },
            {
                "id": "conn_002",
                "provider": "anthropic",
                "authType": "apiKey",
                "name": "user@example.com",
                "priority": 1,
                "isActive": True,
                "testStatus": "active",
                "createdAt": "2025-06-01T00:00:00Z",
                "updatedAt": "2025-06-01T00:00:00Z",
            },
        ],
    }


@pytest.fixture
def mock_onepassword():
    """Mock 1Password items (metadata only, no secrets)."""
    return {
        "mock_items": [
            {
                "id": "item_001",
                "title": "OpenAI API Key",
                "vault": "Personal",
                "tags": ["provider-xref", "api-key", "openai"],
            },
            {
                "id": "item_002",
                "title": "Anthropic API Key",
                "vault": "Personal",
                "tags": ["provider-xref", "api-key", "anthropic"],
            },
        ],
        "mock_credential_ref": {
            "backend": "1password",
            "vault": "Personal",
            "item_id": "item_abc123",
            "field": "credential",
        },
    }


@pytest.fixture
def mock_omniroute_response():
    """The actual response shape from OmniRoute /api/providers."""
    return {
        "connections": [
            {
                "id": "conn_001",
                "provider": "openai",
                "authType": "apiKey",
                "name": "user@example.com",
                "priority": 1,
                "isActive": True,
                "testStatus": "active",
                "createdAt": "2025-06-01T00:00:00Z",
                "updatedAt": "2025-06-01T00:00:00Z",
                "providerSpecificData": {
                    "rateLimitProtection": True,
                },
            },
        ],
        "total": 1,
    }


@pytest.fixture
def fake_api_key():
    """A fake API key that should never appear in state files."""
    return "TEST_SECRET_123_DO_NOT_LEAK"
