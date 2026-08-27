"""
test_phase9_onepassword_item_model.py — Tests for Phase 9D/9E/9F/9G 1Password
authentication and item model.

Tests:
  - Backend detection (service_account vs desktop_cli vs unknown)
  - Write access detection
  - Item title conventions (account login vs API key)
  - Credential ref structure (metadata only, no secrets)
  - Login item lookup (reuse existing)
  - API key item lookup (reuse existing)
  - Item existence check (avoid duplicates)
  - build_credential_ref includes item_title and reference fields
  - No secrets in credential refs
"""

import sys
import os
import json
import re
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adapters.onepassword import (
    detect_auth_backend,
    can_read,
    can_write,
    get_desktop_account,
    require_write_access,
    account_login_title,
    api_key_title,
    find_login_item,
    find_api_key_item,
    item_exists,
    build_credential_ref,
    Adapter as OnePasswordAdapter,
)


# ── Secret scanning helper ─────────────────────────────────────────────────

SECRET_PATTERNS = [
    re.compile(r"cfat_[a-zA-Z0-9_-]+"),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"sk-ant-[a-zA-Z0-9_-]+"),
    re.compile(r"gsk_[a-zA-Z0-9]+"),
    re.compile(r"AIza[a-zA-Z0-9_-]{35}"),
    re.compile(r"fw_[a-zA-Z0-9_-]+"),
]


def scan_for_secrets(obj):
    """Recursively scan an object for known secret patterns."""
    found = []
    if isinstance(obj, str):
        for pat in SECRET_PATTERNS:
            matches = pat.findall(obj)
            for m in matches:
                if len(m) > 16:
                    found.append(m)
    elif isinstance(obj, dict):
        for v in obj.values():
            found.extend(scan_for_secrets(v))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(scan_for_secrets(item))
    return found


# ── Backend detection tests ──────────────────────────────────────────────


class TestBackendDetection:
    """Phase 9D: Detect 1Password auth backend (service account vs desktop)."""

    def test_detect_backend_signed_in_no_service_token(self):
        """When signed in via desktop CLI (no service token), backend is desktop_cli."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="user@example.com\n",
                stderr="",
            )
            with patch.dict(os.environ, {}, clear=True):
                # Ensure OP_SERVICE_ACCOUNT_TOKEN is not set
                os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
                result = detect_auth_backend()
                assert result["signed_in"] is True
                assert result["is_service_account"] is False
                assert result["backend"] == "desktop_cli"

    def test_detect_backend_service_account_token_env(self):
        """When OP_SERVICE_ACCOUNT_TOKEN is set, it's a service account."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="svc_hash_12345\n",
                stderr="",
            )
            with patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "fake_token"}, clear=False):
                result = detect_auth_backend()
                assert result["is_service_account"] is True
                assert result["backend"] == "service_account"

    def test_detect_backend_not_signed_in(self):
        """When op whoami fails, backend is unknown."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="not signed in",
            )
            os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
            result = detect_auth_backend()
            assert result["signed_in"] is False
            assert result["is_service_account"] is False
            assert result["backend"] == "unknown"

    def test_can_read_when_signed_in(self):
        """can_read returns True when signed in."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="user@e.com", stderr="")
            os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
            assert can_read() is True

    def test_can_read_when_not_signed_in(self):
        """can_read returns False when not signed in."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="fail")
            os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
            assert can_read() is False

    def test_can_write_user_account(self):
        """can_write returns True for desktop CLI (user account)."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="user@e.com", stderr="")
            os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
            assert can_write() is True

    def test_can_write_service_account_is_false(self):
        """Service accounts are read-only — can_write returns False."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            # First call: op whoami (for detect_auth_backend)
            # Second call: op whoami --format json (for can_write)
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="svc_hash\n", stderr=""),
                MagicMock(returncode=0, stdout=json.dumps({"account_type": "service-account"}), stderr=""),
            ]
            with patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "fake_token"}, clear=False):
                assert can_write() is False

    def test_require_write_access_ok(self):
        """require_write_access returns (True, None) for user accounts."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="user@e.com", stderr="")
            os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
            ok, msg = require_write_access()
            assert ok is True
            assert msg is None

    def test_require_write_access_blocks_service_account(self):
        """require_write_access returns (False, msg) for service accounts."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="svc_hash\n", stderr=""),
                MagicMock(returncode=0, stdout=json.dumps({"account_type": "service-account"}), stderr=""),
                MagicMock(returncode=0, stdout=json.dumps([{"type": "USER_CREATED", "email": "user@e.com"}]), stderr=""),
            ]
            with patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "fake_token"}, clear=False):
                ok, msg = require_write_access()
                assert ok is False
                assert msg is not None
                assert "read-only" in msg.lower()
                # Must not include the actual token in the message
                assert "fake_token" not in msg

    def test_require_write_access_blocks_unsigned(self):
        """require_write_access returns (False, msg) when not signed in."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not signed in")
            os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
            ok, msg = require_write_access()
            assert ok is False
            assert msg is not None

    def test_detect_backend_never_exposes_token(self):
        """detect_auth_backend must not include the raw token in its output."""
        with patch("adapters.onepassword.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="svc_hash\n", stderr="")
            with patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "supersecret_token_123"}, clear=False):
                result = detect_auth_backend()
                serialized = json.dumps(result, default=str)
                assert "supersecret_token_123" not in serialized


# ── Title convention tests ───────────────────────────────────────────────


class TestTitleConventions:
    """Phase 9E/9F/9K: Verify deterministic 1Password item titles."""

    def test_account_login_title_cloudflare(self):
        """Account login title uses the provider display name."""
        assert account_login_title("Cloudflare") == "Cloudflare"

    def test_account_login_title_openai(self):
        assert account_login_title("OpenAI") == "OpenAI"

    def test_api_key_title_format(self):
        """API key title must be 'OmniRoute [hostname] Api Key'."""
        assert api_key_title("api.cloudflare.com") == "OmniRoute api.cloudflare.com Api Key"
        assert api_key_title("api.openai.com") == "OmniRoute api.openai.com Api Key"
        assert api_key_title("api.groq.com") == "OmniRoute api.groq.com Api Key"

    def test_api_key_title_not_arbitrary(self):
        """Must not produce arbitrary names like 'Cloudflare API Token'."""
        title = api_key_title("api.cloudflare.com")
        assert title != "Cloudflare API Token"
        assert title != "Cloudflare Workers AI Key"
        assert title != "Fireworks Key"
        assert "OmniRoute" in title
        assert "Api Key" in title

    def test_login_and_api_key_are_distinct(self):
        """Account login and API credential must be separate items."""
        login_title = account_login_title("Cloudflare")
        api_title = api_key_title("api.cloudflare.com")
        assert login_title != api_title
        assert "OmniRoute" not in login_title
        assert "OmniRoute" in api_title


# ── Credential ref structure tests ───────────────────────────────────────


class TestCredentialRef:
    """Phase 9E: Credential refs contain metadata only, never secrets."""

    def test_build_credential_ref_has_all_fields(self):
        """build_credential_ref returns all required metadata fields."""
        ref = build_credential_ref(
            vault="Private",
            item_id="item_12345",
            item_title="OmniRoute api.cloudflare.com Api Key",
            field="credential",
        )
        assert ref["backend"] == "1password"
        assert ref["vault"] == "Private"
        assert ref["item_id"] == "item_12345"
        assert ref["item_title"] == "OmniRoute api.cloudflare.com Api Key"
        assert ref["field"] == "credential"
        assert ref["reference"] == "op://Private/item_12345/credential"

    def test_credential_ref_has_no_secret_value(self):
        """The credential ref must not contain the actual password/key."""
        ref = build_credential_ref(
            vault="Private",
            item_id="item_abc",
            item_title="OmniRoute api.test.com Api Key",
            field="credential",
        )
        serialized = json.dumps(ref)
        # No secret patterns should match
        secrets = scan_for_secrets(serialized)
        assert not secrets, f"Secrets in credential ref: {secrets}"

    def test_login_credential_ref_format(self):
        """Login credential ref follows the same metadata-only structure."""
        ref = build_credential_ref(
            vault="Private",
            item_id="login_item_001",
            item_title="Cloudflare",
            field="credential",
        )
        assert ref["backend"] == "1password"
        assert ref["item_title"] == "Cloudflare"
        assert "reference" in ref
        assert ref["reference"].startswith("op://")

    def test_credential_ref_never_has_password_field(self):
        """The ref dict must never have a 'password' key with a value."""
        ref = build_credential_ref(vault="Private", item_id="x1", item_title="Test")
        assert "password" not in ref
        assert "secret" not in ref
        assert "api_key" not in ref
        assert "token" not in ref


# ── Item lookup tests (reuse) ────────────────────────────────────────────


class TestItemLookup:
    """Phase 9G/9K: Find existing items to avoid duplicates."""

    def test_find_login_item_existing(self):
        """find_login_item returns metadata for existing login items."""
        mock_items = [
            {
                "id": "item_001",
                "title": "Cloudflare",
                "vault": {"name": "Private"},
                "details": {
                    "fields": [
                        {"id": "username", "value": "user@example.com"},
                        {"id": "url", "value": "https://dash.cloudflare.com/"},
                    ]
                },
                "tags": ["provider-xref"],
                "created": "2025-06-01T00:00:00Z",
                "updated": "2025-06-01T00:00:00Z",
            },
        ]
        with patch("adapters.onepassword.search_items", return_value=mock_items):
            result = find_login_item("Cloudflare", vault="Private")
            assert result is not None
            assert result["item_id"] == "item_001"
            assert result["title"] == "Cloudflare"
            assert result["username"] == "user@example.com"
            # Must not return the password
            assert "password" not in result
            assert "credential" not in result

    def test_find_login_item_not_found(self):
        """find_login_item returns None when no match exists."""
        with patch("adapters.onepassword.search_items", return_value=[]):
            result = find_login_item("NonExistent", vault="Private")
            assert result is None

    def test_find_api_key_item_existing(self):
        """find_api_key_item returns metadata for existing API key items."""
        mock_items = [
            {
                "id": "item_002",
                "title": "OmniRoute api.cloudflare.com Api Key",
                "vault": {"name": "Private"},
                "details": {"fields": [{"id": "username", "value": ""}]},
                "tags": ["provider-xref", "api-key"],
                "created": "2025-06-01T00:00:00Z",
                "updated": "2025-06-01T00:00:00Z",
            },
        ]
        with patch("adapters.onepassword.search_items", return_value=mock_items):
            result = find_api_key_item("api.cloudflare.com", vault="Private")
            assert result is not None
            assert result["item_id"] == "item_002"
            assert result["title"] == "OmniRoute api.cloudflare.com Api Key"
            # Must not return the actual key
            assert "credential" not in result
            assert "password" not in result

    def test_find_api_key_item_not_found(self):
        """find_api_key_item returns None when no match exists."""
        with patch("adapters.onepassword.search_items", return_value=[]):
            result = find_api_key_item("api.nonexistent.com", vault="Private")
            assert result is None

    def test_item_exists_true(self):
        """item_exists returns True when an item is found."""
        mock_items = [{"id": "item_001", "title": "Cloudflare", "vault": {"name": "Private"}}]
        with patch("adapters.onepassword.search_items", return_value=mock_items):
            assert item_exists("Cloudflare", vault="Private") is True

    def test_item_exists_false(self):
        """item_exists returns False when no item is found."""
        with patch("adapters.onepassword.search_items", return_value=[]):
            assert item_exists("NonExistent", vault="Private") is False

    def test_find_login_item_no_password_leak(self):
        """find_login_item must never return the password value."""
        mock_items = [
            {
                "id": "item_001",
                "title": "Cloudflare",
                "vault": {"name": "Private"},
                "details": {
                    "fields": [
                        {"id": "username", "value": "user@example.com"},
                        {"id": "credential", "value": "super_secret_password_123"},
                    ]
                },
            },
        ]
        with patch("adapters.onepassword.search_items", return_value=mock_items):
            result = find_login_item("Cloudflare", vault="Private")
            assert result is not None
            serialized = json.dumps(result, default=str)
            assert "super_secret_password_123" not in serialized


# ── Adapter class tests ──────────────────────────────────────────────────


class TestOnePasswordAdapter:
    """Phase 9D: Adapter class exposes new auth detection methods."""

    def test_adapter_exposes_auth_methods(self):
        adapter = OnePasswordAdapter()
        assert hasattr(adapter, "detect_auth_backend")
        assert hasattr(adapter, "can_read")
        assert hasattr(adapter, "can_write")
        assert hasattr(adapter, "get_desktop_account")
        assert hasattr(adapter, "require_write_access")
        assert hasattr(adapter, "find_login_item")
        assert hasattr(adapter, "find_api_key_item")
        assert hasattr(adapter, "item_exists")
        assert hasattr(adapter, "account_login_title")
        assert hasattr(adapter, "api_key_title")
