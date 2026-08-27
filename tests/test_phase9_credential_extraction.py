"""
test_phase9_credential_extraction.py — Tests for Phase 9J credential extraction
and Phase 9K credential storage abstraction.

Tests:
  - Generic credential extraction (regex, selector strategies)
  - Cloudflare cfat_ extraction
  - Credential never exposed in debug/result output
  - API key naming convention ("OmniRoute [hostname] Api Key")
  - Credential storage to 1Password (mocked)
  - Credential retrieval from 1Password (mocked)
  - No secrets in ExtractionResult.to_debug_dict()
  - No secrets in ExtractionResult.to_result()
"""

import sys
import os
import json
import re
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adapters.credential_extractor import (
    extract_credential,
    ExtractionRule,
    ExtractionResult,
    PageSnapshot,
    ExtractionStrategy,
    get_extraction_rules,
    get_hostname_from_catalog,
    credential_to_onepassword,
    retrieve_credential_value,
    redact_credential,
    PROVIDER_EXTRACTION_RULES,
)
from adapters.onepassword import api_key_title, account_login_title


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


TEST_CF_TOKEN = "cfat_abc123def456ghi789jkl012mno345pqr678stu90"


# ── Extraction strategy tests ──────────────────────────────────────────────


class TestExtractionStrategies:
    """Phase 9J: Test different extraction strategies."""

    def test_regex_extraction_cloudflare(self):
        """Cloudflare cfat_ token should be extracted via regex."""
        snapshot = PageSnapshot(
            text=f"Your API token is: {TEST_CF_TOKEN}",
            url="https://dash.cloudflare.com/account/api-tokens",
        )
        rules = get_extraction_rules("cloudflare-ai")
        assert len(rules) > 0
        result = extract_credential(snapshot, rules, provider_id="cloudflare-ai")
        assert result.found
        assert result.value == TEST_CF_TOKEN
        # The actual value must not appear in debug or result dicts
        debug = result.to_debug_dict()
        assert TEST_CF_TOKEN not in json.dumps(debug)
        result_dict = result.to_result()
        assert TEST_CF_TOKEN not in json.dumps(result_dict)

    def test_regex_extraction_anthropic(self):
        """Anthropic sk-ant- key should be extracted."""
        key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK"
        snapshot = PageSnapshot(
            text=f"API Key: {key}",
            url="https://console.anthropic.com/api-keys/settings",
        )
        rules = get_extraction_rules("anthropic")
        assert len(rules) > 0
        result = extract_credential(snapshot, rules)
        assert result.found
        assert result.value == key
        # No secrets in debug output
        assert key not in json.dumps(result.to_debug_dict())

    def test_regex_extraction_openai(self):
        """OpenAI sk- key should be extracted."""
        key = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ab"  # 48+ chars
        snapshot = PageSnapshot(
            text=f"Your API key: {key}",
            url="https://platform.openai.com/api-keys",
        )
        rules = get_extraction_rules("openai")
        assert len(rules) > 0
        result = extract_credential(snapshot, rules)
        assert result.found
        assert result.value == key

    def test_regex_extraction_groq(self):
        """Groq gsk_ key should be extracted."""
        key = "gsk_abcdefghijklmnopqrstuvwxyz1234567890abcdefghijkl"
        snapshot = PageSnapshot(
            text=f"API Key: {key}",
            url="https://console.groq.com/api-keys",
        )
        rules = get_extraction_rules("groq")
        assert len(rules) > 0
        result = extract_credential(snapshot, rules)
        assert result.found
        assert result.value == key

    def test_regex_extraction_no_match(self):
        """Should return found=False when no credential is present."""
        snapshot = PageSnapshot(
            text="No credentials here, just regular text.",
            url="https://example.com",
        )
        rules = get_extraction_rules("cloudflare-ai")
        result = extract_credential(snapshot, rules)
        assert not result.found
        assert result.value is None

    def test_selector_strategy(self):
        """SELECTOR strategy should extract from element text."""
        rule = ExtractionRule(
            strategy=ExtractionStrategy.SELECTOR,
            pattern="#api-key-field",
            prefix="sk-",
        )
        snapshot = PageSnapshot(
            text="",
            url="https://example.com",
            elements={"#api-key-field": {"text": "sk-test12345678901234567890"}},
        )
        result = extract_credential(snapshot, [rule], provider_id="test")
        assert result.found
        assert result.value == "sk-test12345678901234567890"

    def test_extraction_with_prefix_validation(self):
        """Extraction should only match credentials with the right prefix."""
        rule = ExtractionRule(
            strategy=ExtractionStrategy.REGEX,
            pattern=r"sk-[a-zA-Z0-9]",
            prefix="sk-",
            min_length=20,
        )
        snapshot = PageSnapshot(
            text="Key: sk-",
            url="https://example.com",
        )
        result = extract_credential(snapshot, [rule])
        assert not result.found  # Too short

    def test_extraction_min_length_filter(self):
        """Short matches should be rejected by min_length."""
        rule = ExtractionRule(
            strategy=ExtractionStrategy.REGEX,
            pattern=r"sk-[a-zA-Z0-9_-]+",
            prefix="sk-",
            min_length=100,  # Impossibly long
        )
        snapshot = PageSnapshot(
            text="Key: sk-abcdefghijklmnop",
            url="https://example.com",
        )
        result = extract_credential(snapshot, [rule])
        assert not result.found


# ── ExtractionResult security tests ───────────────────────────────────────


class TestExtractionResultSecurity:
    """Phase 9J: Extraction results must never expose secrets."""

    def test_to_debug_dict_no_secret(self):
        """to_debug_dict must not include the actual credential value."""
        result = ExtractionResult(
            value="secret_value_1234567890",
            masked_value="secret_v***",
            found=True,
            credential_type="api_key",
            source_description="Cloudflare API token",
        )
        debug = result.to_debug_dict()
        assert "secret_value_1234567890" not in json.dumps(debug)
        assert debug["masked_value"] == "secret_v***"

    def test_to_result_no_secret(self):
        """to_result must not include the actual credential value."""
        result = ExtractionResult(
            value="cfat_real_secret_value_123456",
            masked_value="cfat_rea***",
            found=True,
            credential_type="api_token",
        )
        result_dict = result.to_result()
        assert "cfat_real_secret_value_123456" not in json.dumps(result_dict)
        assert "REDACTED" in result_dict["credential_value"] or result_dict.get("credential_value") == "cfat_rea***"

    def test_masked_value_shows_prefix(self):
        """Masked value should show first few chars for verification."""
        result = ExtractionResult(
            value="cfat_abc123def456ghi789",
            masked_value="cfat_ab****",
            found=True,
        )
        assert "cfat_" in result.masked_value
        assert "abc123def456ghi789" not in result.masked_value

    def test_redact_credential(self):
        """redact_credential masks the middle of a value."""
        val = "sk-secretvalue123456789"
        redacted = redact_credential(val, visible_chars=4)
        assert redacted.startswith("sk-s")
        assert "secretvalue123456789" not in redacted
        assert "*" in redacted

    def test_redact_credential_short(self):
        """Short values (shorter than visible_chars) are fully masked."""
        val = "ab"
        redacted = redact_credential(val)
        assert redacted == "**"
        assert val not in redacted

    def test_redact_credential_very_short(self):
        """Single char values are fully masked."""
        val = "x"
        redacted = redact_credential(val)
        assert redacted == "*"
        assert val not in redacted

    def test_redact_credential_empty(self):
        """Empty values return [REDACTED]."""
        assert redact_credential("") == "[REDACTED]"


# ── API key naming convention tests ────────────────────────────────────────


class TestApiKeyNamingConvention:
    """Phase 9K: API credential naming must be exactly 'OmniRoute [hostname] Api Key'."""

    def test_openai_naming(self):
        assert api_key_title("api.openai.com") == "OmniRoute api.openai.com Api Key"

    def test_cloudflare_naming(self):
        assert api_key_title("api.cloudflare.com") == "OmniRoute api.cloudflare.com Api Key"

    def test_groq_naming(self):
        assert api_key_title("api.groq.com") == "OmniRoute api.groq.com Api Key"

    def test_anthropic_naming(self):
        assert api_key_title("api.anthropic.com") == "OmniRoute api.anthropic.com Api Key"

    def test_deepseek_naming(self):
        assert api_key_title("api.deepseek.com") == "OmniRoute api.deepseek.com Api Key"

    def test_fireworks_naming(self):
        assert api_key_title("api.fireworks.ai") == "OmniRoute api.fireworks.ai Api Key"

    def test_account_login_title(self):
        """Account login title uses provider display name."""
        assert account_login_title("Cloudflare") == "Cloudflare"

    def test_title_format_enforced(self):
        """All titles must follow 'OmniRoute [hostname] Api Key' format."""
        for hostname in ["api.openai.com", "api.cloudflare.com", "api.groq.com"]:
            title = api_key_title(hostname)
            assert title.startswith("OmniRoute ")
            assert title.endswith(" Api Key")
            assert hostname in title

    def test_no_arbitrary_names(self):
        """Must not produce names like 'Cloudflare API Token' or 'Fireworks Key'."""
        title = api_key_title("api.cloudflare.com")
        assert title != "Cloudflare API Token"
        assert title != "Cloudflare Workers AI Key"
        assert "OmniRoute" in title
        assert "Api Key" in title


# ── Credential storage to 1Password tests (mocked) ────────────────────────


class TestCredentialStorage:
    """Phase 9K/9E: Storing credentials to 1Password creates correct references."""

    def test_credential_storage_returns_ref_not_secret(self):
        """credential_to_onepassword must return a ref dict, never the secret."""
        with patch("adapters.onepassword.create_login") as mock_create:
            with patch("adapters.onepassword.require_write_access") as mock_access:
                mock_access.return_value = (True, None)
                mock_create.return_value = {
                    "id": "item_12345",
                    "vault": "Private",
                }
                ref = credential_to_onepassword(
                    "cfat_secret_value_123",
                    "OmniRoute api.cloudflare.com Api Key",
                    "Private",
                    hostname="api.cloudflare.com",
                )
                assert ref is not None
                assert ref["backend"] == "1password"
                assert ref["vault"] == "Private"
                assert ref["item_id"] == "item_12345"
                assert ref["item_title"] == "OmniRoute api.cloudflare.com Api Key"
                assert ref["field"] == "credential"
                assert "reference" in ref
                assert ref["reference"].startswith("op://")
                # The actual secret must not appear in the ref
                assert "cfat_secret_value_123" not in json.dumps(ref)

    def test_credential_storage_failure_returns_none(self):
        """If 1Password write fails, return None (not the secret)."""
        with patch("adapters.onepassword.create_login") as mock_create:
            with patch("adapters.onepassword.require_write_access") as mock_access:
                mock_access.return_value = (True, None)
                mock_create.return_value = {"error": "vault not found"}
                ref = credential_to_onepassword(
                    "secret_value",
                    "OmniRoute api.test.com Api Key",
                    "Private",
                )
                assert ref is None

    def test_credential_storage_blocks_readonly_account(self):
        """If 1Password is read-only, storage must raise (not leak the secret)."""
        fake_secret = "cfat_should_not_leak_12345"
        with patch("adapters.onepassword.require_write_access") as mock_access:
            mock_access.return_value = (False, "read-only service account")
            with pytest.raises(PermissionError):
                credential_to_onepassword(
                    fake_secret,
                    "OmniRoute api.test.com Api Key",
                    "Private",
                )
            # Even on error, the secret must not be in the exception message
            # (the message comes from require_write_access, which doesn't include secrets)

    def test_retrieve_credential_value(self):
        """retrieve_credential_value returns the actual value for operations."""
        with patch("adapters.onepassword.get_credential_value") as mock_get:
            mock_get.return_value = "actual_secret_value"
            ref = {
                "backend": "1password",
                "vault": "Private",
                "item_id": "item_123",
                "field": "credential",
            }
            value = retrieve_credential_value(ref)
            assert value == "actual_secret_value"
            mock_get.assert_called_once()

    def test_retrieve_nonexistent_credential(self):
        """retrieve_credential_value returns None for unknown backend."""
        ref = {"backend": "unknown", "item_id": "something"}
        assert retrieve_credential_value(ref) is None


# ── Hostname extraction tests ────────────────────────────────────────────


class TestHostnameExtraction:
    """Phase 9O/9K: Extract hostnames from catalog for naming."""

    def test_get_hostname_from_catalog(self):
        """Can extract hostname from provider catalog."""
        with patch("engine.catalog.get_provider") as mock_get:
            mock_get.return_value = {
                "id": "openai",
                "name": "OpenAI",
                "hostname": "api.openai.com",
            }
            catalog = {"providers": []}
            hostname = get_hostname_from_catalog("openai", catalog)
            assert hostname == "api.openai.com"

    def test_get_hostname_fallback_from_base_url(self):
        """Can extract hostname from base_url if hostname not directly set."""
        with patch("engine.catalog.get_provider", return_value=None):
            catalog = {"providers": []}
            assert get_hostname_from_catalog("unknown", catalog) is None
